package main

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	composeProjectLabel = "com.docker.compose.project"
	composeServiceLabel = "com.docker.compose.service"
	composeContNumLabel = "com.docker.compose.container-number"

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

var (
	errShuttingDown = errors.New("shutting down")
	localAddr       = netip.MustParseAddr("127.0.0.1")
)

func (r *ruleManager) createRules(ctx context.Context) {
	for container := range r.createCh {
		if err := r.createRule(ctx, container); err != nil {
			if errors.Is(err, errShuttingDown) {
				return
			}
			r.logger.Error("error creating rules",
				zap.String("container.id", container.ID[:12]),
				zap.String("container.name", stripName(container.Name)),
				zap.Error(err),
			)
		}
	}
}

func (r *ruleManager) createRule(ctx context.Context, container types.ContainerJSON) error {
	contName := stripName(container.Name)
	logger := r.logger.With(zap.String("container.id", container.ID[:12]), zap.String("container.name", contName))

	logger.Info("adding rules")

	// parse rules config if the rules label exists; if the label
	// does not exist, no rules will be added but all traffic to
	// and from the container will still be dropped
	var rulesCfg config
	cfg, configExists := container.Config.Labels[rulesLabel]
	if configExists {
		if err := yaml.Unmarshal([]byte(cfg), &rulesCfg); err != nil {
			return fmt.Errorf("error parsing rules: %w", err)
		}
		if err := validateConfig(rulesCfg); err != nil {
			return fmt.Errorf("error validating rules: %w", err)
		}
	}
	project := container.Config.Labels[composeProjectLabel]

	// ensure specified networks and containers in rules are valid
	addrs := make(map[string][]byte, len(container.NetworkSettings.Networks))
	for netName, netSettings := range container.NetworkSettings.Networks {
		addr, err := netip.ParseAddr(netSettings.IPAddress)
		if err != nil {
			return fmt.Errorf("error parsing IP of container: %q: %w", contName, err)
		}
		addrs[netName] = ref(addr.As4())[:]
	}

	nfc, err := nftables.New()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}

	// create chain for this container's rules
	nftRules := make([]*nftables.Rule, 0, len(rulesCfg.Output)*2)
	contChainName := buildChainName(contName, container.ID)
	chain := &nftables.Chain{
		Name:  contChainName,
		Table: r.chain.Table,
		Type:  nftables.ChainTypeFilter,
	}
	nfc.AddChain(chain)

	// if no rules were explicitly specified, only the rule that drops
	// traffic to/from the container will be added
	estContainers := make(map[string]struct{})
	if configExists {
		if err := r.validateRuleNetworks(ctx, rulesCfg, project, addrs, estContainers); err != nil {
			return fmt.Errorf("error validating rules: %w", err)
		}

		// handle port mapping rules
		var err error
		var hostRules []*nftables.Rule
		nftRules, hostRules, err = r.createPortMappingRules(logger, container, contName, rulesCfg.MappedPorts, addrs, chain, nftRules)
		if err != nil {
			return fmt.Errorf("error creating port mapping rules: %w", err)
		}
		for _, hostRule := range hostRules {
			nfc.AddRule(hostRule)
		}

		// handle outbound rules
		nftRules, err = r.createOutputRules(ctx, rulesCfg.Output, project, addrs, chain, container.ID, nftRules)
		if err != nil {
			return fmt.Errorf("error creating output rules: %w", err)
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
	curRules, err := nfc.GetRules(r.chain.Table, r.chain)
	if err != nil {
		return fmt.Errorf("error getting rules of %q: %w", r.chain.Name, err)
	}
	for i := range nftRules {
		if nftRules[i].Chain.Name == mainChainName {
			if findRule(logger, nftRules[i], curRules) {
				nftRules = slices.Delete(nftRules, i, i)
			}
		}
	}
	// insert rules in reverse order that they were created in to maintain order
	for i := len(nftRules) - 1; i >= 0; i-- {
		nfc.InsertRule(nftRules[i])
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

	if err := nfc.SetAddElements(r.containerAddrSet, addrElems); err != nil {
		return fmt.Errorf("error adding elements to set %q: %w", r.containerAddrSet.Name, err)
	}

	if err := nfc.Flush(); err != nil {
		return fmt.Errorf("error flushing nftables commands: %w", err)
	}

	logger.Debug("adding to database")
	service := container.Config.Labels[composeServiceLabel]

	return r.addContainer(ctx, logger, container.ID, contName, service, addrs, estContainers)
}

// container name appears with prefix "/"
func stripName(name string) string {
	if len(name) > 0 && name[0] == '/' {
		name = name[1:]
	}
	return name
}

func (r *ruleManager) validateRuleNetworks(ctx context.Context, cfg config, project string, addrs map[string][]byte, estContainers map[string]struct{}) error {
	var listedConts []types.Container
	var err error

	// only get a list of containers if at least one rule specifies a
	// container
	i := slices.IndexFunc(cfg.Output, func(r ruleConfig) bool {
		return r.Container != ""
	})
	if i != -1 {
		listedConts, err = r.dockerCli.ContainerList(ctx, types.ContainerListOptions{})
		if err != nil {
			return fmt.Errorf("error listing running containers: %w", err)
		}
	}

	containers := make(map[string]types.ContainerJSON)
	for i, ruleCfg := range cfg.Output {
		// ensure the specified network exist
		if ruleCfg.Network != "" {
			if _, _, ok := findNetwork(ruleCfg.Network, project, addrs); !ok {
				return fmt.Errorf("output rule #%d: network %q not found",
					i,
					ruleCfg.Network,
				)
			}
		}

		// ensure the specified container exists and is a member of
		// the specified network
		if ruleCfg.Container != "" {
			var found bool
			for _, listedCont := range listedConts {
				if !containerNameMatches(ruleCfg.Container, listedCont.Labels, listedCont.Names...) {
					continue
				}
				estContainers[listedCont.ID] = struct{}{}
				found = true

				container, ok := containers[ruleCfg.Container]
				if !ok {
					container, err = r.dockerCli.ContainerInspect(ctx, listedCont.ID)
					if err != nil {
						return fmt.Errorf("error inspecting container %s: %w", ruleCfg.Container, err)
					}
					containers[ruleCfg.Container] = container
				}

				netName, network, ok := findNetwork(ruleCfg.Network, project, container.NetworkSettings.Networks)
				if !ok {
					return fmt.Errorf("output rule #%d: network %q not found for container %q",
						i,
						ruleCfg.Network,
						ruleCfg.Container,
					)
				}

				addr, err := netip.ParseAddr(network.IPAddress)
				if err != nil {
					return fmt.Errorf("error parsing IP of container %q from network %q: %w", ruleCfg.Container, netName, err)
				}
				cfg.Output[i].IP = addrOrRange{
					addr: addr,
				}
				break
			}

			if !found {
				// we need to add rules to this container's chain,
				// but it hasn't been started yet
				found, err := r.processRequiredContainers(ctx, ruleCfg.Container)
				if err != nil {
					return fmt.Errorf("error handling required container %q: %w", ruleCfg.Container, err)
				}
				if !found {
					return fmt.Errorf("output rule #%d: container %q not found",
						i,
						ruleCfg.Container,
					)
				}

				// fetch running containers again so if another rule requires
				// this container it will find it
				listedConts, err = r.dockerCli.ContainerList(ctx, types.ContainerListOptions{})
				if err != nil {
					return fmt.Errorf("error listing running containers: %w", err)
				}
				// add container to list of established containers
				for _, listedCont := range listedConts {
					if containerNameMatches(ruleCfg.Container, listedCont.Labels, listedCont.Names...) {
						estContainers[listedCont.ID] = struct{}{}
						break
					}
				}
			}
		}
	}

	return nil
}

func findNetwork[T any](network, project string, addrs map[string]T) (string, T, bool) {
	var zero T
	netNames := []string{
		network,
		project + "_" + network,
	}
	for _, netName := range netNames {
		v, ok := addrs[netName]
		if ok {
			return netName, v, true
		}
	}

	return "", zero, false
}

func containerNameMatches(expectedName string, labels map[string]string, names ...string) bool {
	if len(expectedName) == 0 {
		return false
	}

	// maybe user prefixed a backslash already?
	if slices.Contains(names, expectedName) {
		return true
	}
	// docker prepends a backslash to container names
	slashPrefix := expectedName[0] == '/'
	if !slashPrefix && slices.Contains(names, "/"+expectedName) {
		return true
	}
	// if the user did prefix a slash, remove it here so we hopefully
	// get a match; the service name won't be prefixed with a backslash
	if slashPrefix {
		expectedName = expectedName[1:]
	}
	// check if the docker compose service name matches
	if serviceName, ok := labels[composeServiceLabel]; ok && serviceName == expectedName {
		return true
	}

	return false
}

func (r *ruleManager) processRequiredContainers(ctx context.Context, contName string) (bool, error) {
	found := false
	timer := time.NewTimer(containerStartTimeout)

	for !found {
		select {
		case c, ok := <-r.createCh:
			if !ok {
				return false, errShuttingDown
			}
			if !timer.Stop() {
				<-timer.C
			}

			if err := r.createRule(ctx, c); err != nil {
				return false, err
			}

			if containerNameMatches(contName, c.Config.Labels, c.Name) {
				found = true
			} else {
				timer.Reset(containerStartTimeout)
			}
		case <-timer.C:
			// timeout elapsed, container doesn't exist or is being very
			// slow to start
			return false, nil
		}
	}

	return true, nil
}

func buildChainName(name, id string) string {
	return fmt.Sprintf("%s%s-%s", chainPrefix, name, id[:12])
}

func (r *ruleManager) createPortMappingRules(logger *zap.Logger, container types.ContainerJSON, contName string, mappedPortsCfg mappedPorts, addrs map[string][]byte, chain *nftables.Chain, nftRules []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule, error) {
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
	if (mappedPortsCfg.Localhost.Allow || mappedPortsCfg.External.Allow) && !hasMappedPorts {
		logger.Warn("local and/or external access to mapped ports is allowed, but there are not any mapped ports")
		return nftRules, nil, nil
	}
	if !hasMappedPorts {
		return nftRules, nil, nil
	}

	hostPortRules := make(map[uint16][]*nftables.Rule)
	for netName, netSettings := range container.NetworkSettings.Networks {
		gateway, err := netip.ParseAddr(netSettings.Gateway)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing gateway of network: %w", err)
		}

		for port, hostPorts := range container.NetworkSettings.Ports {
			localAllowed := mappedPortsCfg.Localhost.Allow
			for _, hostPort := range hostPorts {
				addr, err := netip.ParseAddr(hostPort.HostIP)
				if err != nil {
					return nil, nil, fmt.Errorf("error parsing IP of port mapping: %w", err)
				}
				// TODO: support IPv6
				if addr.Is6() {
					continue
				}

				// TODO: make same checks for external
				if localAllowed && !addr.IsUnspecified() && addr != localAddr {
					logger.Sugar().Warnf("local access to mapped ports is allowed, but port %s is listening on %s which is not accessible to localhost",
						hostPort.HostPort,
						addr,
					)
					continue
				}
				if !localAllowed && !addr.IsUnspecified() && addr != localAddr {
					// local access is not allowed, but localhost won't
					// be able to reach this port anyway since it isn't
					// listening on 0.0.0.0 or 127.0.0.1, so no need to
					// create any drop rules
					continue
				}

				if localAllowed && (!mappedPortsCfg.External.Allow || mappedPortsCfg.External.IP.IsValid()) {
					// Create rules to allow/drop traffic from container
					// network gateway to container; this will only be hit
					// for traffic originating from localhost after being
					// NATed by docker rules. If all external inbound
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
							Verdict: mappedPortsCfg.Localhost.Verdict,
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

	hostRules := make([]*nftables.Rule, 0, len(hostPortRules)*2)
	for _, rules := range hostPortRules {
		hostRules = append(hostRules, rules...)
	}

	return nftRules, hostRules, nil
}

func (r *ruleManager) createOutputRules(ctx context.Context, ruleCfgs []ruleConfig, project string, addrs map[string][]byte, chain *nftables.Chain, condID string, nftRules []*nftables.Rule) ([]*nftables.Rule, error) {
	for _, ruleCfg := range ruleCfgs {
		rule := ruleDetails{
			inbound: false,
			cfg:     ruleCfg,
			allow:   true,
			chain:   chain,
			contID:  condID,
		}

		if ruleCfg.Network != "" {
			_, addr, ok := findNetwork(ruleCfg.Network, project, addrs)
			if !ok {
				return nil, fmt.Errorf("network %q not found", ruleCfg.Network)
			}
			rule.addr = addr

			if ruleCfg.Container != "" {
				id, name, err := r.getContainerIDAndName(ctx, ruleCfg.Container)
				if err != nil && errors.Is(err, sql.ErrNoRows) {
					// we need to add rules to this container's chain,
					// but rules haven't been added to it yet
					var found bool
					found, err = r.processRequiredContainers(ctx, ruleCfg.Container)
					if err != nil {
						return nil, fmt.Errorf("error handling required container %q: %w", ruleCfg.Container, err)
					}
					if !found {
						return nil, fmt.Errorf("container %q not found", ruleCfg.Container)
					}
					id, name, err = r.getContainerIDAndName(ctx, ruleCfg.Container)
				}
				if err != nil {
					return nil, fmt.Errorf("error getting container %q ID from database: %w", ruleCfg.Container, err)
				}
				rule.estChain = &nftables.Chain{
					Table: r.chain.Table,
					Name:  buildChainName(name, id),
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

func (r *ruleManager) getContainerIDAndName(ctx context.Context, contName string) (string, string, error) {
	name := contName

	id, err := r.db.GetContainerID(ctx, contName)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", "", fmt.Errorf("error getting container %q ID from database: %w", contName, err)
		}

		info, err := r.db.GetContainerIDAndNameFromAlias(ctx, contName)
		if err != nil {
			return "", "", fmt.Errorf("error getting container %q ID from database: %w", contName, err)
		}

		id = info.ID
		name = info.Name
	}

	return id, name, nil
}

type ruleDetails struct {
	inbound  bool
	addr     []byte
	cfg      ruleConfig
	allow    bool
	chain    *nftables.Chain
	estChain *nftables.Chain
	contID   string
}

func createNFTRules(r ruleDetails) []*nftables.Rule {
	rules := make([]*nftables.Rule, 0, 3)
	// TODO: delete rule from est chain when container is deleted
	if r.estChain == nil {
		r.estChain = r.chain
	}

	if r.cfg.Verdict.Queue == 0 {
		if r.allow {
			return append(rules,
				createNFTRule(r.inbound, stateNewEst, r.addr, r.cfg, 0, true, r.chain, r.contID),
				createNFTRule(!r.inbound, stateEst, r.addr, r.cfg, 0, true, r.estChain, r.contID),
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
			createNFTRule(false, stateEst, r.addr, r.cfg, r.cfg.Verdict.OutputEstQueue, r.allow, r.estChain, r.contID),
		)
	} else if !r.inbound && r.cfg.Verdict.Queue == r.cfg.Verdict.OutputEstQueue {
		// if rule is outbound and queue and established outbound queue
		// are the same, create one rule for outbound traffic
		rules = append(rules,
			createNFTRule(false, stateNewEst, r.addr, r.cfg, r.cfg.Verdict.Queue, r.allow, r.chain, r.contID),
			createNFTRule(true, stateEst, r.addr, r.cfg, r.cfg.Verdict.InputEstQueue, r.allow, r.estChain, r.contID),
		)
	} else if r.inbound {
		// if rule is inbound and queue and established inbound queue
		// are different, need to create separate rules for them
		rules = append(rules,
			createNFTRule(true, stateNew, r.addr, r.cfg, r.cfg.Verdict.Queue, r.allow, r.chain, r.contID),
			createNFTRule(true, stateEst, r.addr, r.cfg, r.cfg.Verdict.InputEstQueue, r.allow, r.chain, r.contID),
			createNFTRule(false, stateEst, r.addr, r.cfg, r.cfg.Verdict.OutputEstQueue, r.allow, r.estChain, r.contID),
		)
	} else if !r.inbound {
		// if rule is outbound and queue and established outbound queue
		// are different, need to create separate rules for them
		rules = append(rules,
			createNFTRule(false, stateNew, r.addr, r.cfg, r.cfg.Verdict.Queue, r.allow, r.chain, r.contID),
			createNFTRule(false, stateEst, r.addr, r.cfg, r.cfg.Verdict.OutputEstQueue, r.allow, r.chain, r.contID),
			createNFTRule(true, stateEst, r.addr, r.cfg, r.cfg.Verdict.InputEstQueue, r.allow, r.estChain, r.contID),
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
