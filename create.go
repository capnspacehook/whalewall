package main

import (
	"context"
	"encoding/binary"
	"log"
	"net/netip"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	srcAddrOffset = 12
	dstAddrOffset = 16
	srcPortOffset = 0
	dstPortOffset = 2

	stateNew    = expr.CtStateBitNEW
	stateEst    = expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED
	stateNewEst = stateNew | stateEst
)

func (r *ruleManager) createRules(ctx context.Context, ch <-chan types.ContainerJSON) {
	for container := range ch {
		// container name appears with prefix "/"
		containerName := strings.Replace(container.Name, "/", "", 1)
		log.Printf("adding rules for %q", containerName)

		var rulesCfg config
		cfg, configExists := container.Config.Labels[rulesLabel]
		if configExists {
			if err := yaml.Unmarshal([]byte(cfg), &rulesCfg); err != nil {
				log.Printf("error parsing rules: %v", err)
				continue
			}
			if err := validateConfig(rulesCfg); err != nil {
				log.Printf("error validating rules: %v", err)
				continue
			}
		}

		addrs := make(map[string][]byte, len(container.NetworkSettings.Networks))
		for netName, netSettings := range container.NetworkSettings.Networks {
			addr, err := netip.ParseAddr(netSettings.IPAddress)
			if err != nil {
				log.Printf("error parsing IP of container: %q: %v", containerName, err)
				continue
			}
			addrb := ref(addr.As4())[:]
			reverse(addrb)
			addrs[netName] = addrb
		}

		if configExists && !r.validateRuleNetworks(ctx, rulesCfg, addrs) {
			continue
		}

		nftRules := make([]*nftables.Rule, 0, (len(rulesCfg.Input)+len(rulesCfg.Output))*2)

		// handle outbound rules
		for _, ruleCfg := range rulesCfg.Output {
			if ruleCfg.Network != "" {
				nftRules = append(nftRules,
					r.createNFTRules(false, addrs[ruleCfg.Network], ruleCfg, container.ID)...,
				)
			} else {
				for _, addr := range addrs {
					nftRules = append(
						nftRules, r.createNFTRules(false, addr, ruleCfg, container.ID)...,
					)
				}
			}
		}
		// handle inbound rules
		for _, ruleCfg := range rulesCfg.Input {
			if ruleCfg.Network != "" {
				nftRules = append(
					nftRules, r.createNFTRules(true, addrs[ruleCfg.Network], ruleCfg, container.ID)...,
				)
			} else {
				for _, addr := range addrs {
					nftRules = append(
						nftRules, r.createNFTRules(true, addr, ruleCfg, container.ID)...,
					)
				}
			}
		}
		// ensure we aren't creating existing rules
		if configExists {
			curRules, err := r.nfc.GetRules(r.chain.Table, r.chain)
			if err != nil {
				log.Printf("error getting rules of %q: %v", r.chain.Name, err)
				continue
			}
			for i := range nftRules {
				if findRule(nftRules[i], curRules) {
					nftRules = slices.Delete(nftRules, i, i)
				}
			}
		}
		// insert rules in reverse order that they were created in to maintain order
		for i := len(nftRules) - 1; i >= 0; i-- {
			r.nfc.InsertRule(nftRules[i])
		}

		// handle deny all out
		elements := make([]nftables.SetElement, 0, len(addrs))
		for _, addr := range addrs {
			elements = append(elements, nftables.SetElement{
				Key: addr,
			})
		}
		if err := r.nfc.SetAddElements(r.dropSet, elements); err != nil {
			log.Printf("error adding set elements: %v", err)
		}

		if err := r.nfc.Flush(); err != nil {
			log.Printf("error flushing nftables commands: %v", err)
			continue
		}

		r.addContainer(ctx, container.ID, containerName, addrs)
	}
}

func (r *ruleManager) validateRuleNetworks(ctx context.Context, cfg config, addrs map[string][]byte) bool {
	var listedConts []types.Container
	var err error

	inIdx := slices.IndexFunc(cfg.Input, func(r ruleConfig) bool {
		return r.Container != ""
	})
	outIdx := slices.IndexFunc(cfg.Output, func(r ruleConfig) bool {
		return r.Container != ""
	})
	if inIdx != -1 || outIdx != -1 {
		filter := filters.NewArgs(filters.KeyValuePair{
			Key:   "status",
			Value: "running",
		})
		listedConts, err = r.dockerCli.ContainerList(ctx, types.ContainerListOptions{Filters: filter})
		if err != nil {
			log.Printf("error listing running containers: %v", err)
			return false
		}
	}

	containers := make(map[string]types.ContainerJSON)
	validateNetworks := func(rulesCfg []ruleConfig, direction string) bool {
		for i, ruleCfg := range rulesCfg {
			// ensure the specified network exist
			if ruleCfg.Network != "" {
				if _, ok := addrs[ruleCfg.Network]; !ok {
					// docker compose will prepend "docker_" to network names
					dockerNetName := "docker_" + ruleCfg.Network
					addr, ok := addrs[dockerNetName]
					if !ok {
						log.Printf("error validating rules: %s rule #%d: network %q not found",
							direction,
							i,
							ruleCfg.Network,
						)
						return false
					}

					// move address to network name the user specified
					delete(addrs, dockerNetName)
					addrs[ruleCfg.Network] = addr
				}
			}
			// ensure the specified container exists and is a member of
			// the specified network
			if ruleCfg.Container != "" {
				var found bool
				slashName := "/" + ruleCfg.Container
				for _, listedCont := range listedConts {
					if !slices.Contains(listedCont.Names, slashName) {
						continue
					}
					found = true

					container, ok := containers[ruleCfg.Container]
					if !ok {
						container, err = r.dockerCli.ContainerInspect(ctx, listedCont.ID)
						if err != nil {
							log.Printf("error inspecting container %s: %v", ruleCfg.Container, err)
							return false
						}
						containers[ruleCfg.Container] = container
					}

					netName := ruleCfg.Network
					network, ok := container.NetworkSettings.Networks[netName]
					if !ok {
						// docker compose will prepend "docker_" to network names
						netName = "docker_" + netName
						network, ok = container.NetworkSettings.Networks[netName]
						if !ok {
							log.Printf("error validating rules: %s rule #%d: network %q not found for container %q",
								direction,
								i,
								ruleCfg.Network,
								ruleCfg.Container,
							)
							return false
						}
					}

					addr, err := netip.ParseAddr(network.IPAddress)
					if err != nil {
						log.Printf("error parsing IP of container: %q: %v", ruleCfg.Container, err)
						return false
					}
					rulesCfg[i].IP = addr
				}

				if !found {
					log.Printf("error validating rules: %s rule #%d: container %q not found",
						direction,
						i,
						ruleCfg.Container,
					)
					return false
				}
			}
		}

		return true
	}

	if !validateNetworks(cfg.Input, "input") {
		return false
	}
	if !validateNetworks(cfg.Output, "output") {
		return false
	}

	return true
}

func (r *ruleManager) createNFTRules(inbound bool, addr []byte, cfg ruleConfig, contID string) []*nftables.Rule {
	rules := make([]*nftables.Rule, 0, 3)
	if cfg.Queue == 0 {
		return append(rules,
			r.createNFTRule(inbound, stateNewEst, addr, cfg, 0, contID),
			r.createNFTRule(!inbound, stateEst, addr, cfg, 0, contID),
		)
	}

	if inbound && cfg.Queue == cfg.InputEstQueue {
		// if rule is inbound and queue and established inbound queue
		// are the same, create one rule for inbound traffic
		rules = append(rules,
			r.createNFTRule(true, stateNewEst, addr, cfg, cfg.Queue, contID),
			r.createNFTRule(false, stateEst, addr, cfg, cfg.OutputEstQueue, contID),
		)
	} else if !inbound && cfg.Queue == cfg.OutputEstQueue {
		// if rule is outbound and queue and established outbound queue
		// are the same, create one rule for outbound traffic
		rules = append(rules,
			r.createNFTRule(false, stateNewEst, addr, cfg, cfg.Queue, contID),
			r.createNFTRule(true, stateEst, addr, cfg, cfg.InputEstQueue, contID),
		)
	} else if inbound {
		// if rule is inbound and queue and established inbound queue
		// are different, need to create separate rules for them
		rules = append(rules,
			r.createNFTRule(true, stateNew, addr, cfg, cfg.Queue, contID),
			r.createNFTRule(true, stateEst, addr, cfg, cfg.InputEstQueue, contID),
			r.createNFTRule(false, stateEst, addr, cfg, cfg.OutputEstQueue, contID),
		)
	} else if !inbound {
		// if rule is outbound and queue and established outbound queue
		// are different, need to create separate rules for them
		rules = append(rules,
			r.createNFTRule(false, stateNew, addr, cfg, cfg.Queue, contID),
			r.createNFTRule(false, stateEst, addr, cfg, cfg.OutputEstQueue, contID),
			r.createNFTRule(true, stateEst, addr, cfg, cfg.InputEstQueue, contID),
		)
	}

	return rules
}

func (r *ruleManager) createNFTRule(inbound bool, state uint32, addr []byte, cfg ruleConfig, queueNum uint16, contID string) *nftables.Rule {
	addrOffset := srcAddrOffset
	portOffset := dstPortOffset
	if inbound {
		addrOffset = dstAddrOffset
		portOffset = srcPortOffset
	}
	proto := unix.IPPROTO_TCP
	if cfg.Proto == "udp" {
		proto = unix.IPPROTO_UDP
	}

	exprs := make([]expr.Any, 0, 13)
	if cfg.IP.IsValid() {
		srcAddr := addr
		dstAddr := ref(cfg.IP.As4())[:]
		if inbound {
			srcAddr, dstAddr = dstAddr, srcAddr
		}

		exprs = append(exprs,
			// [ payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        uint32(srcAddrOffset),
				DestRegister:  1,
			},
			// [ cmp eq reg 1 ... ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     srcAddr,
			},
			// [ payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        uint32(dstAddrOffset),
				DestRegister:  1,
			},
			// [ cmp eq reg 1 ... ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     dstAddr,
			},
		)
	} else {
		exprs = append(exprs,
			// [ payload load 4b @ network header + ... => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        uint32(addrOffset),
				DestRegister:  1,
			},
			// [ cmp eq reg 1 ... ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     addr[:],
			},
		)
	}
	if cfg.Proto != "" {
		exprs = append(exprs,
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			// [ cmp eq reg 1 ... ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{byte(proto)},
			},
		)
	}
	if cfg.Port != 0 {
		exprs = append(exprs,
			// [ payload load 2b @ transport header + ... => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           2,
				Base:          expr.PayloadBaseTransportHeader,
				Offset:        uint32(portOffset),
				DestRegister:  1,
			},
			// [ cmp eq reg 1 ... ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binary.BigEndian.AppendUint16(nil, cfg.Port),
			},
		)
	}
	exprs = append(exprs,
		// [ ct load state => reg 1 ]
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: 1,
		},
		// [ bitwise reg 1 = ( reg 1 & ... ) ^ 0x00000000 ]
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binary.LittleEndian.AppendUint32(nil, state),
			Xor:            []byte{0, 0, 0, 0},
		},
		// [ cmp neq reg 1 0x00000000 ]
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
		&expr.Counter{},
	)
	if cfg.Chain != "" {
		exprs = append(exprs,
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: cfg.Chain,
			},
		)
	} else if queueNum != 0 {
		exprs = append(exprs,
			&expr.Queue{
				Num: queueNum,
			},
		)
	} else {
		exprs = append(exprs,
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		)
	}

	return &nftables.Rule{
		Table:    r.chain.Table,
		Chain:    r.chain,
		Exprs:    exprs,
		UserData: []byte(contID),
	}
}

func ref[T any](v T) *T {
	return &v
}

// adapted from https://github.com/golang/go/wiki/SliceTricks#reversing
func reverse[S ~[]E, E any](s S) {
	for i := len(s)/2 - 1; i >= 0; i-- {
		opp := len(s) - 1 - i
		s[i], s[opp] = s[opp], s[i]
	}
}
