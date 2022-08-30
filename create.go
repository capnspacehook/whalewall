package main

import (
	"encoding/binary"
	"log"
	"net/netip"
	"strings"

	"github.com/docker/docker/api/types"
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
)

func (r *ruleManager) createRules(ch <-chan *types.ContainerJSON) {
	for container := range ch {
		// container name appears with prefix "/"
		containerName := strings.Replace(container.Name, "/", "", 1)
		log.Printf("adding rules for %q", containerName)

		cfg := container.Config.Labels[rulesLabel]
		var rulesCfg config
		if err := yaml.Unmarshal([]byte(cfg), &rulesCfg); err != nil {
			log.Printf("error parsing rules: %v", err)
			continue
		}
		if err := validateConfig(rulesCfg); err != nil {
			log.Printf("error validating rules: %v", err)
			continue
		}

		addrs := make(map[string][]byte, len(container.NetworkSettings.Networks))
		for netName, netSettings := range container.NetworkSettings.Networks {
			addr, err := netip.ParseAddr(netSettings.IPAddress)
			if err != nil {
				log.Printf("error parsing container IP: %v", err)
				continue
			}
			addrs[netName] = ref(addr.As4())[:]
		}

		validateNetworks := func(rulesCfg []ruleConfig, direction string) bool {
			for i, ruleCfg := range rulesCfg {
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
			}

			return true
		}
		if !validateNetworks(rulesCfg.Input, "input") {
			continue
		}
		if !validateNetworks(rulesCfg.Output, "output") {
			continue
		}

		// TODO: handle IPv6
		var nftRules []*nftables.Rule

		// handle outbound rules
		for _, ruleCfg := range rulesCfg.Output {
			if ruleCfg.Network != "" {
				nftRules = append(nftRules, r.createNFTRules(false, addrs[ruleCfg.Network], ruleCfg, container.ID)...)
			} else {
				for _, addr := range addrs {
					nftRules = append(nftRules, r.createNFTRules(false, addr, ruleCfg, container.ID)...)
				}
			}
		}

		// handle inbound rules
		for _, ruleCfg := range rulesCfg.Input {
			if ruleCfg.Network != "" {
				nftRules = append(nftRules, r.createNFTRules(true, addrs[ruleCfg.Network], ruleCfg, container.ID)...)
			} else {
				for _, addr := range addrs {
					nftRules = append(nftRules, r.createNFTRules(true, addr, ruleCfg, container.ID)...)
				}
			}
		}

		// ensure we aren't creating existing rules
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

		// handle deny all out
		elements := make([]nftables.SetElement, 0, len(addrs))
		for _, addr := range addrs {
			elements = append(elements, nftables.SetElement{
				Key: addr,
			})
		}

		err = r.nfc.SetAddElements(r.dropSet, elements)
		if err != nil {
			log.Printf("error adding set elements: %v", err)
		}

		// insert rules in reverse order that they were created in to maintain order
		for i := len(nftRules) - 1; i >= 0; i-- {
			r.nfc.InsertRule(nftRules[i])
		}

		if err := r.nfc.Flush(); err != nil {
			log.Printf("error flushing commands: %v", err)
			continue
		}

		c := &containerInfo{
			Name:   containerName,
			Addrs:  addrs,
			Config: rulesCfg,
			Rules:  nftRules,
		}
		r.addContainer(container.ID, c)
	}
}

func (r *ruleManager) createNFTRules(inbound bool, addr []byte, cfg ruleConfig, contID string) []*nftables.Rule {
	return []*nftables.Rule{
		r.createNFTRule(inbound, true, addr, cfg, contID),
		r.createNFTRule(!inbound, false, addr, cfg, contID),
	}
}

func (r *ruleManager) createNFTRule(inbound, new bool, addr []byte, cfg ruleConfig, contID string) *nftables.Rule {
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
	connState := expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED
	if new {
		connState |= expr.CtStateBitNEW
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
			Mask:           binary.LittleEndian.AppendUint32(nil, connState),
			Xor:            []byte{0, 0, 0, 0},
		},
		// [ cmp neq reg 1 0x00000000 ]
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	)

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
