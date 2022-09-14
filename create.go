package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	chainPrefix = "whalewall-"

	containerStartTimeout = 5 * time.Second

	srcAddrOffset = 12
	dstAddrOffset = 16
	srcPortOffset = 0
	dstPortOffset = 2

	stateNew    = expr.CtStateBitNEW
	stateEst    = expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED
	stateNewEst = stateNew | stateEst
)

var localAddr = netip.MustParseAddr("127.0.0.1")

func (r *ruleManager) createRules(ctx context.Context, ch <-chan types.ContainerJSON) {
	for container := range ch {
		r.createRule(ctx, container, ch)
	}
}

func (r *ruleManager) createRule(ctx context.Context, container types.ContainerJSON, ch <-chan types.ContainerJSON) error {
	// container name appears with prefix "/"
	contName := strings.Replace(container.Name, "/", "", 1)
	log.Printf("adding rules for %q", contName)

	// parse rules config if the rules label exists; if the label
	// does not exist, no rules will be added but all traffic to
	// and from the container will still be dropped
	var rulesCfg config
	cfg, configExists := container.Config.Labels[rulesLabel]
	if configExists {
		if err := yaml.Unmarshal([]byte(cfg), &rulesCfg); err != nil {
			return fmt.Errorf("error parsing rules: %v", err)
		}
		if err := validateConfig(rulesCfg); err != nil {
			return fmt.Errorf("error validating rules: %v", err)
		}
	}

	// ensure specified networks and containers in rules are valid
	addrs := make(map[string][]byte, len(container.NetworkSettings.Networks))
	for netName, netSettings := range container.NetworkSettings.Networks {
		addr, err := netip.ParseAddr(netSettings.IPAddress)
		if err != nil {
			return fmt.Errorf("error parsing IP of container: %q: %v", contName, err)
		}
		addrs[netName] = ref(addr.As4())[:]
	}

	// create chain for this container's rules
	nftRules := make([]*nftables.Rule, 0, (len(rulesCfg.Input)+len(rulesCfg.Output))*2)
	contChainName := buildChainName(contName, container.ID)
	chain := &nftables.Chain{
		Name:  contChainName,
		Table: r.chain.Table,
		Type:  nftables.ChainTypeFilter,
	}
	r.nfc.AddChain(chain)

	// if no rules were explicitly specified, only the rule that drops
	// traffic to/from the container will be added
	if configExists {
		if err := r.validateRuleNetworks(ctx, rulesCfg, addrs, ch); err != nil {
			return fmt.Errorf("error validating rules: %v", err)
		}

		// handle port mapping rules
		var err error
		nftRules, err = r.createPortMappingRules(container, contName, rulesCfg.MappedPorts, addrs, chain, nftRules)
		if err != nil {
			return fmt.Errorf("error creating port mapping rules: %v", err)
		}
		// handle inbound rules
		nftRules, err = r.createStandardRules(ctx, true, rulesCfg.Input, addrs, chain, container.ID, nftRules)
		if err != nil {
			return fmt.Errorf("error creating input rules: %v", err)
		}
		// handle outbound rules
		nftRules, err = r.createStandardRules(ctx, false, rulesCfg.Output, addrs, chain, container.ID, nftRules)
		if err != nil {
			return fmt.Errorf("error creating output rules: %v", err)
		}
	}

	// create rule to drop all not explicitly allowed traffic
	logPrefix := strings.ToUpper(contChainName) + " DROP: "
	nftRules = append(nftRules,
		&nftables.Rule{
			Table: chain.Table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Counter{},
				&expr.Log{
					Key:   (1 << unix.NFTA_LOG_PREFIX) | (1 << unix.NFTA_LOG_LEVEL),
					Level: expr.LogLevelInfo,
					Data:  []byte(logPrefix),
				},
				&expr.Verdict{
					Kind: expr.VerdictDrop,
				},
			},
			UserData: []byte(container.ID),
		},
	)

	// ensure we aren't creating existing rules
	curRules, err := r.nfc.GetRules(r.chain.Table, r.chain)
	if err != nil {
		return fmt.Errorf("error getting rules of %q: %v", r.chain.Name, err)
	}
	for i := range nftRules {
		if nftRules[i].Chain.Name == mainChainName {
			if findRule(nftRules[i], curRules) {
				nftRules = slices.Delete(nftRules, i, i)
			}
		}
	}
	// insert rules in reverse order that they were created in to maintain order
	for i := len(nftRules) - 1; i >= 0; i-- {
		r.nfc.InsertRule(nftRules[i])
	}

	// add container IPs to jump set so traffic to/from this
	// container will go to the correct chain
	addrElems := make([]nftables.SetElement, 0, len(addrs))
	for _, addr := range addrs {
		addrElems = append(addrElems, nftables.SetElement{
			Key: addr,
			VerdictData: &expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: contChainName,
			},
		})
	}

	if err := r.nfc.SetAddElements(r.containerAddrSet, addrElems); err != nil {
		return fmt.Errorf("error adding elements to set %q: %v", r.containerAddrSet.Name, err)
	}

	if err := r.nfc.Flush(); err != nil {
		return fmt.Errorf("error flushing nftables commands: %v", err)
	}

	log.Printf("adding %q to database", contName)

	return r.addContainer(ctx, container.ID, contName, addrs)
}

func (r *ruleManager) validateRuleNetworks(ctx context.Context, cfg config, addrs map[string][]byte, ch <-chan types.ContainerJSON) error {
	var listedConts []types.Container
	var err error

	// only get a list of containers if at least one rule specifies a
	// container
	inIdx := slices.IndexFunc(cfg.Input, func(r ruleConfig) bool {
		return r.Container != ""
	})
	outIdx := slices.IndexFunc(cfg.Output, func(r ruleConfig) bool {
		return r.Container != ""
	})
	if inIdx != -1 || outIdx != -1 {
		listedConts, err = r.dockerCli.ContainerList(ctx, types.ContainerListOptions{})
		if err != nil {
			return fmt.Errorf("error listing running containers: %v", err)
		}
	}

	containers := make(map[string]types.ContainerJSON)
	validateNetworks := func(rulesCfg []ruleConfig, direction string) error {
		for i, ruleCfg := range rulesCfg {
			// ensure the specified network exist
			if ruleCfg.Network != "" {
				if _, _, ok := findNetwork(ruleCfg.Network, addrs); !ok {
					return fmt.Errorf("%s rule #%d: network %q not found",
						direction,
						i,
						ruleCfg.Network,
					)
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
							return fmt.Errorf("error inspecting container %s: %v", ruleCfg.Container, err)
						}
						containers[ruleCfg.Container] = container
					}

					netName, network, ok := findNetwork(ruleCfg.Network, container.NetworkSettings.Networks)
					if !ok {
						return fmt.Errorf("%s rule #%d: network %q not found for container %q",
							direction,
							i,
							ruleCfg.Network,
							ruleCfg.Container,
						)
					}

					addr, err := netip.ParseAddr(network.IPAddress)
					if err != nil {
						return fmt.Errorf("error parsing IP of container %q from network %q: %v", ruleCfg.Container, netName, err)
					}
					rulesCfg[i].IP = addrOrRange{
						addr: addr,
					}
					break
				}

				if !found {
					found, err := r.processRequiredContainers(ctx, slashName, ch)
					if err != nil {
						return err
					}
					if !found {
						return fmt.Errorf("%s rule #%d: container %q not found",
							direction,
							i,
							ruleCfg.Container,
						)
					}

					listedConts, err = r.dockerCli.ContainerList(ctx, types.ContainerListOptions{})
					if err != nil {
						return fmt.Errorf("error listing running containers: %v", err)
					}
				}
			}
		}

		return nil
	}

	if err := validateNetworks(cfg.Input, "input"); err != nil {
		return err
	}
	if err := validateNetworks(cfg.Output, "output"); err != nil {
		return err
	}

	return nil
}

func findNetwork[T any](network string, addrs map[string]T) (string, T, bool) {
	var zero T
	netNames := []string{
		network,
		"compose_" + network,
		"docker_" + network,
	}
	for _, netName := range netNames {
		v, ok := addrs[netName]
		if ok {
			return netName, v, true
		}
	}

	return "", zero, false
}

func (r *ruleManager) processRequiredContainers(ctx context.Context, name string, ch <-chan types.ContainerJSON) (bool, error) {
	found := false
	timer := time.NewTimer(containerStartTimeout)

	for !found {
		select {
		case c := <-ch:
			if !timer.Stop() {
				<-timer.C
			}

			if err := r.createRule(ctx, c, ch); err != nil {
				return false, err
			}

			if c.Name == name {
				found = true

			} else {
				timer.Reset(containerStartTimeout)
			}
		case <-timer.C:
			return false, nil
		}
	}

	return true, nil
}

func buildChainName(name, id string) string {
	return fmt.Sprintf("%s%s-%s", chainPrefix, name, id[:12])
}

func (r *ruleManager) createPortMappingRules(container types.ContainerJSON, contName string, mappedPortsCfg mappedPorts, addrs map[string][]byte, chain *nftables.Chain, nftRules []*nftables.Rule) ([]*nftables.Rule, error) {
	// check if there are any mapped ports to create rules for
	var hasMappedPorts bool
	for _, hostPorts := range container.NetworkSettings.Ports {
		// if an image exposes a port but no mapped ports are configured,
		// the container port it will be here with no host ports
		if len(hostPorts) != 0 {
			hasMappedPorts = true
			break
		}
	}
	if (mappedPortsCfg.Local.Allow || mappedPortsCfg.External.Allow) && !hasMappedPorts {
		log.Printf("local and/or external access to mapped ports was allowed, but there are not any mapped ports for container %q",
			contName,
		)
		return nftRules, nil
	}
	if !hasMappedPorts {
		return nftRules, nil
	}

	hostPortRules := make(map[uint16][]*nftables.Rule)
	for netName, netSettings := range container.NetworkSettings.Networks {
		gateway, err := netip.ParseAddr(netSettings.Gateway)
		if err != nil {
			return nil, fmt.Errorf("error parsing gateway of network: %v", err)
		}

		for port, hostPorts := range container.NetworkSettings.Ports {
			// create rules to allow/drop traffic from localhost to container
			localAllowed := mappedPortsCfg.Local.Allow
			for _, hostPort := range hostPorts {
				addr, err := netip.ParseAddr(hostPort.HostIP)
				if err != nil {
					return nil, fmt.Errorf("error parsing IP of port mapping: %v", err)
				}
				// TODO: support IPv6
				if addr.Is6() {
					continue
				}

				if !localAllowed {
					// create rules to drop traffic from localhost to
					// mapped port
					hostPortInt, err := strconv.ParseUint(hostPort.HostPort, 10, 16)
					if err != nil {
						return nil, fmt.Errorf("error parsing port of port mapping: %v", err)
					}

					rule := ruleDetails{
						inbound: true,
						cfg: ruleConfig{
							IP: addrOrRange{
								addr: localAddr,
							},
							Proto:   port.Proto(),
							Port:    uint16(hostPortInt),
							Verdict: mappedPortsCfg.Local.Verdict,
						},
						allow:  false,
						chain:  r.chain,
						contID: container.ID,
					}
					// since these rules won't have a destination
					// IP, ensure they won't be added multiple times
					if _, ok := hostPortRules[uint16(hostPortInt)]; !ok {
						hostPortRules[uint16(hostPortInt)] = createNFTRules(rule)
					}
				} else if !mappedPortsCfg.External.Allow || mappedPortsCfg.External.IP.IsValid() {
					// Create rules to allow/drop traffic from container
					// network gateway to container; this will only be hit
					// for traffic originating from localhost after being
					// NATed by docker rules.I f all external inbound
					// traffic is allowed, creating this is pointless as
					// the rule to allow all external inbound traffic will
					// cover traffic from the gateway too.
					rule := ruleDetails{
						inbound: true,
						addr:    addrs[netName],
						cfg: ruleConfig{
							IP: addrOrRange{
								addr: gateway,
							},
							Proto:   port.Proto(),
							Port:    uint16(port.Int()),
							Verdict: mappedPortsCfg.Local.Verdict,
						},
						allow:  true,
						chain:  chain,
						contID: container.ID,
					}
					nftRules = append(nftRules,
						createNFTRules(rule)...,
					)
				}
			}

			if mappedPortsCfg.External.Allow {
				// create rules to allow external traffic to container
				rule := ruleDetails{
					inbound: true,
					addr:    addrs[netName],
					cfg: ruleConfig{
						IP:      mappedPortsCfg.External.IP,
						Proto:   port.Proto(),
						Port:    uint16(port.Int()),
						Verdict: mappedPortsCfg.External.Verdict,
					},
					allow:  true,
					chain:  chain,
					contID: container.ID,
				}
				nftRules = append(nftRules,
					createNFTRules(rule)...,
				)
			}
		}
	}

	for _, rules := range hostPortRules {
		for _, rule := range rules {
			r.nfc.AddRule(rule)
		}
	}

	return nftRules, nil
}

func (r *ruleManager) createStandardRules(ctx context.Context, inbound bool, ruleCfgs []ruleConfig, addrs map[string][]byte, chain *nftables.Chain, condID string, nftRules []*nftables.Rule) ([]*nftables.Rule, error) {
	for _, ruleCfg := range ruleCfgs {
		rule := ruleDetails{
			inbound: inbound,
			cfg:     ruleCfg,
			allow:   true,
			chain:   chain,
			contID:  condID,
		}

		if ruleCfg.Network != "" {
			_, addr, ok := findNetwork(ruleCfg.Network, addrs)
			if !ok {
				return nil, fmt.Errorf("network %q not found", ruleCfg.Network)
			}
			rule.addr = addr

			if ruleCfg.Container != "" {
				// TODO: process other containers it not found
				id, err := r.db.GetContainerID(ctx, ruleCfg.Container)
				if err != nil {
					return nil, fmt.Errorf("error getting container ID from database: %v", err)
				}
				rule.estContID = id
				rule.estChain = &nftables.Chain{
					Table: r.chain.Table,
					Name:  buildChainName(ruleCfg.Container, id),
				}
			}

			nftRules = append(nftRules,
				createNFTRules(rule)...,
			)
		} else {
			for _, addr := range addrs {
				rule.addr = addr
				nftRules = append(nftRules,
					createNFTRules(rule)...,
				)
			}
		}
	}

	return nftRules, nil
}

type ruleDetails struct {
	inbound   bool
	addr      []byte
	cfg       ruleConfig
	allow     bool
	chain     *nftables.Chain
	estChain  *nftables.Chain
	contID    string
	estContID string
}

func createNFTRules(r ruleDetails) []*nftables.Rule {
	rules := make([]*nftables.Rule, 0, 3)
	// TODO: delete rule from est chain when container is deleted
	if r.estChain == nil {
		r.estChain = r.chain
	}
	if r.estContID == "" {
		r.estContID = r.contID
	}

	if r.cfg.Verdict.Queue == 0 {
		if r.allow {
			return append(rules,
				createNFTRule(r.inbound, stateNewEst, r.addr, r.cfg, 0, true, r.chain, r.contID),
				createNFTRule(!r.inbound, stateEst, r.addr, r.cfg, 0, true, r.estChain, r.estContID),
			)
		} else {
			return append(rules,
				createNFTRule(r.inbound, stateNew, r.addr, r.cfg, 0, false, r.chain, r.contID),
			)
		}
	}

	if r.inbound && r.cfg.Verdict.Queue == r.cfg.Verdict.InputEstQueue {
		// if rule is inbound and queue and established inbound queue
		// are the same, create one rule for inbound traffic
		rules = append(rules,
			createNFTRule(true, stateNewEst, r.addr, r.cfg, r.cfg.Verdict.Queue, r.allow, r.chain, r.contID),
			createNFTRule(false, stateEst, r.addr, r.cfg, r.cfg.Verdict.OutputEstQueue, r.allow, r.estChain, r.estContID),
		)
	} else if !r.inbound && r.cfg.Verdict.Queue == r.cfg.Verdict.OutputEstQueue {
		// if rule is outbound and queue and established outbound queue
		// are the same, create one rule for outbound traffic
		rules = append(rules,
			createNFTRule(false, stateNewEst, r.addr, r.cfg, r.cfg.Verdict.Queue, r.allow, r.chain, r.contID),
			createNFTRule(true, stateEst, r.addr, r.cfg, r.cfg.Verdict.InputEstQueue, r.allow, r.estChain, r.estContID),
		)
	} else if r.inbound {
		// if rule is inbound and queue and established inbound queue
		// are different, need to create separate rules for them
		rules = append(rules,
			createNFTRule(true, stateNew, r.addr, r.cfg, r.cfg.Verdict.Queue, r.allow, r.chain, r.contID),
			createNFTRule(true, stateEst, r.addr, r.cfg, r.cfg.Verdict.InputEstQueue, r.allow, r.chain, r.contID),
			createNFTRule(false, stateEst, r.addr, r.cfg, r.cfg.Verdict.OutputEstQueue, r.allow, r.estChain, r.estContID),
		)
	} else if !r.inbound {
		// if rule is outbound and queue and established outbound queue
		// are different, need to create separate rules for them
		rules = append(rules,
			createNFTRule(false, stateNew, r.addr, r.cfg, r.cfg.Verdict.Queue, r.allow, r.chain, r.contID),
			createNFTRule(false, stateEst, r.addr, r.cfg, r.cfg.Verdict.OutputEstQueue, r.allow, r.chain, r.contID),
			createNFTRule(true, stateEst, r.addr, r.cfg, r.cfg.Verdict.InputEstQueue, r.allow, r.estChain, r.estContID),
		)
	}

	return rules
}

func createNFTRule(inbound bool, state uint32, addr []byte, cfg ruleConfig, queueNum uint16, allow bool, chain *nftables.Chain, contID string) *nftables.Rule {
	addrOffset := srcAddrOffset
	cfgAddrOffset := dstAddrOffset
	portOffset := srcPortOffset
	if inbound {
		addrOffset = dstAddrOffset
		cfgAddrOffset = srcAddrOffset
	}
	if state&stateNew != 0 {
		portOffset = dstPortOffset
	}
	proto := unix.IPPROTO_TCP
	if cfg.Proto == "udp" {
		proto = unix.IPPROTO_UDP
	}

	exprs := make([]expr.Any, 0, 15)
	if cfg.IP.IsValid() {
		if cfgAddr, ok := cfg.IP.Addr(); ok {
			var addrExprs []expr.Any
			if len(addr) != 0 {
				addrExprs = matchIPExprs(addr, addrOffset)
			}
			cfgAddrExprs := matchIPExprs(ref(cfgAddr.As4())[:], cfgAddrOffset)
			if inbound {
				exprs = append(exprs, cfgAddrExprs...)
				exprs = append(exprs, addrExprs...)
			} else {
				exprs = append(exprs, addrExprs...)
				exprs = append(exprs, cfgAddrExprs...)
			}
		} else if lowAddr, highAddr, ok := cfg.IP.Range(); ok {
			var addrExprs []expr.Any
			if len(addr) != 0 {
				addrExprs = matchIPExprs(addr, addrOffset)
			}
			rangeExprs := []expr.Any{
				// [ payload load 4b @ network header + ... => reg 1 ]
				&expr.Payload{
					OperationType: expr.PayloadLoad,
					Len:           4,
					Base:          expr.PayloadBaseNetworkHeader,
					Offset:        uint32(cfgAddrOffset),
					DestRegister:  1,
				},
				// [ cmp gte reg 1 ... ]
				&expr.Cmp{
					Op:       expr.CmpOpGte,
					Register: 1,
					Data:     ref(lowAddr.As4())[:],
				},
				// [ cmp lte reg 1 ... ]
				&expr.Cmp{
					Op:       expr.CmpOpLte,
					Register: 1,
					Data:     ref(highAddr.As4())[:],
				},
			}
			if inbound {
				exprs = append(exprs, rangeExprs...)
				exprs = append(exprs, addrExprs...)
			} else {
				exprs = append(exprs, addrExprs...)
				exprs = append(exprs, rangeExprs...)
			}
		} else {
			// should never happen if cfg.IP.IsValid is true
			panic("invalid addrOrRange")
		}
	} else if len(addr) != 0 {
		exprs = append(exprs, matchIPExprs(addr, addrOffset)...)
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
	if cfg.Verdict.Chain != "" {
		exprs = append(exprs,
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: cfg.Verdict.Chain,
			},
		)
	} else if queueNum != 0 {
		exprs = append(exprs,
			&expr.Queue{
				Num: queueNum,
			},
		)
	} else {
		verdict := expr.VerdictDrop
		if allow {
			verdict = expr.VerdictAccept
		}
		exprs = append(exprs,
			&expr.Verdict{
				Kind: verdict,
			},
		)
	}

	return &nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		Exprs:    exprs,
		UserData: []byte(contID),
	}
}

func matchIPExprs(addr []byte, offset int) []expr.Any {
	return []expr.Any{
		// [ payload load 4b @ network header + ... => reg 1 ]
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			Len:           4,
			Base:          expr.PayloadBaseNetworkHeader,
			Offset:        uint32(offset),
			DestRegister:  1,
		},
		// [ cmp eq reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     addr,
		},
	}
}

func ref[T any](v T) *T {
	return &v
}
