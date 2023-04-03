package whalewall

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	"github.com/capnspacehook/whalewall/database"
)

const (
	hostNetworkName = "host"

	composeProjectLabel = "com.docker.compose.project"
	composeServiceLabel = "com.docker.compose.service"
	composeContNumLabel = "com.docker.compose.container-number"

	chainPrefix = "whalewall-"

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

	localAddr     = netip.MustParseAddr("127.0.0.1")
	zeroUint32    = []byte{0, 0, 0, 0}
	acceptVerdict = &expr.Verdict{
		Kind: expr.VerdictAccept,
	}
	dropVerdict = &expr.Verdict{
		Kind: expr.VerdictDrop,
	}
)

// createRules adds nftables rules for started containers.
func (r *RuleManager) createRules(ctx context.Context) {
	for container := range r.createCh {
		if err := r.createContainerRules(ctx, container); err != nil {
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

// createContainerRules adds nftables rules for a container.
func (r *RuleManager) createContainerRules(ctx context.Context, container types.ContainerJSON) error {
	contName := stripName(container.Name)
	logger := r.logger.With(zap.String("container.id", container.ID[:12]), zap.String("container.name", contName))
	logger.Info("creating rules")

	// check that network settings are valid
	if container.NetworkSettings == nil {
		return fmt.Errorf("container %q has no network settings", contName)
	}
	if len(container.NetworkSettings.Networks) == 1 {
		if _, ok := container.NetworkSettings.Networks[hostNetworkName]; ok {
			return fmt.Errorf("container %q is using host networking, rules cannot be created for it", contName)
		}
	}

	// parse rules config if the rules label exists; if the label
	// does not exist, no rules will be added but all traffic to
	// and from the container will still be dropped
	var rulesCfg config
	cfg, configExists := container.Config.Labels[rulesLabel]
	if configExists {
		dec := yaml.NewDecoder(strings.NewReader(cfg))
		dec.KnownFields(true)
		if err := dec.Decode(&rulesCfg); err != nil {
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

	nfc, err := r.newFirewallClient()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}

	// create chain for this container's rules
	nftRules := make([]*nftables.Rule, 0, len(rulesCfg.Output)*2)
	contChainName := buildChainName(contName, container.ID)
	chain := &nftables.Chain{
		Name:  contChainName,
		Table: filterTable,
		Type:  nftables.ChainTypeFilter,
	}
	nfc.AddChain(chain)

	// if no rules were explicitly specified, only the rule that drops
	// traffic to/from the container will be added
	estContainers := make(map[string]struct{})
	service := container.Config.Labels[composeServiceLabel]
	if configExists {
		if err := r.populateOutputRules(ctx, rulesCfg, container.ID, project, addrs, estContainers); err != nil {
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
		nftRules, err = r.createOutputRules(ctx, logger, rulesCfg.Output, project, addrs, chain, contName, container.ID, nftRules)
		if err != nil {
			return fmt.Errorf("error creating output rules: %w", err)
		}
	}

	// create rules that allow traffic from another container to this
	// container if necessary that couldn't be created before
	nftRules, err = r.createWaitingContainerRules(ctx, logger, container.ID, contName, service, project, addrs, chain, estContainers, nftRules)
	if err != nil {
		return fmt.Errorf("error creating waiting output rules: %w", err)
	}

	// create rule to drop all not explicitly allowed traffic
	nftRules = append(nftRules, createDropRule(chain, container.ID))

	// ensure we aren't creating existing rules
	curRules, err := nfc.GetRules(filterTable, whalewallChain)
	if err != nil {
		return fmt.Errorf("error getting rules of %q: %w", whalewallChainName, err)
	}
	for i := range nftRules {
		if nftRules[i].Chain.Name == whalewallChainName {
			if findRule(logger, nftRules[i], curRules) {
				nftRules = slices.Delete(nftRules, i, i+1)
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

	if err := nfc.SetAddElements(containerAddrSet, addrElems); err != nil {
		return fmt.Errorf("error adding elements to set %q: %w", containerAddrSetName, err)
	}

	if err := nfc.Flush(); err != nil {
		return fmt.Errorf("error flushing nftables commands: %w", err)
	}

	logger.Debug("adding to database")

	return r.addContainer(ctx, logger, container.ID, contName, service, addrs, estContainers)
}

// stripName removes the leading "/" from a container name if necessary.
func stripName(name string) string {
	if len(name) > 0 && name[0] == '/' {
		name = name[1:]
	}
	return name
}

// populateOutputRules attempts to find the IPs of containers specified
// in output rules and fills the rules appropriately.
func (r *RuleManager) populateOutputRules(ctx context.Context, cfg config, id, project string, addrs map[string][]byte, estConts map[string]struct{}) error {
	// only get a list of containers if at least one rule specifies a
	// container
	i := slices.IndexFunc(cfg.Output, func(r ruleConfig) bool {
		return r.Container != ""
	})
	if i == -1 {
		return nil
	}
	listedConts, err := withTimeout(ctx, r.timeout, func(ctx context.Context) ([]types.Container, error) {
		return r.dockerCli.ContainerList(ctx, types.ContainerListOptions{})
	})
	if err != nil {
		return fmt.Errorf("error listing running containers: %w", err)
	}

	containers := make(map[string]types.ContainerJSON)
	for i, ruleCfg := range cfg.Output {
		// ensure the specified network exists
		if ruleCfg.Network != "" {
			if _, _, ok := findNetwork(ruleCfg.Network, project, addrs); !ok {
				return fmt.Errorf("output rule #%d: network %q not found",
					i,
					ruleCfg.Network,
				)
			}
		}

		if ruleCfg.Container != "" {
			// if the specified container is started, check that whalewall
			// is enabled for it and that it is a member of the specified
			// network
			var found bool
			for _, listedCont := range listedConts {
				if !containerNameMatches(ruleCfg.Container, listedCont.Labels, listedCont.Names...) {
					continue
				}

				// validate container settings
				cont, ok := containers[ruleCfg.Container]
				if !ok {
					cont, err = withTimeout(ctx, r.timeout, func(ctx context.Context) (types.ContainerJSON, error) {
						return r.dockerCli.ContainerInspect(ctx, listedCont.ID)
					})
					if err != nil {
						return fmt.Errorf("error inspecting container %s", listedCont.ID[:12])
					}
					enabled, err := whalewallEnabled(cont.Config.Labels)
					if err != nil {
						return fmt.Errorf("error parsing container %q label: %w", cont.ID[:12], err)
					}
					if !enabled {
						return fmt.Errorf("output rule #%d: container %q does not have whalewall enabled",
							i,
							ruleCfg.Container,
						)
					}
					containers[ruleCfg.Container] = cont
				}
				dstProject := cont.Config.Labels[composeProjectLabel]
				dstNetName, dstNetwork, ok := findNetwork(ruleCfg.Network, dstProject, cont.NetworkSettings.Networks)
				if !ok {
					return fmt.Errorf("output rule #%d: network %q not found for container %q",
						i,
						ruleCfg.Network,
						ruleCfg.Container,
					)
				}

				// if the container exists in the database it's been
				// processed already, and we can create rules involving
				// it now
				exists, err := r.containerExists(ctx, cont.ID)
				if err != nil {
					return fmt.Errorf("error querying container %s from database: %w", cont.ID[:12], err)
				}
				if !exists {
					break
				}
				estConts[cont.ID] = struct{}{}
				found = true

				addr, err := netip.ParseAddr(dstNetwork.IPAddress)
				if err != nil {
					return fmt.Errorf("error parsing IP of container %q from network %q: %w", ruleCfg.Container, dstNetName, err)
				}
				cfg.Output[i].IP = addrOrRange{
					addr: addr,
				}
				break
			}

			if !found {
				// we need to add rules to this container's chain, but it
				// hasn't been processed yet; add the rule to the database
				// so when we are processing this container, this rule will
				// be created
				var buf bytes.Buffer
				encoder := gob.NewEncoder(&buf)
				if err := encoder.Encode(ruleCfg); err != nil {
					return fmt.Errorf("error encoding waiting container rule: %w", err)
				}
				err := r.db.AddWaitingContainerRule(ctx, database.AddWaitingContainerRuleParams{
					SrcContainerID:   id,
					DstContainerName: ruleCfg.Container,
					Rule:             buf.Bytes(),
				})
				if err != nil {
					return fmt.Errorf("error adding waiting container rule to database: %w", err)
				}
				cfg.Output[i].skip = true
			}
		}
	}

	return nil
}

// findNetwork attempts to find a given Docker network, returning the
// name the network was found by if possible. Docker Compose sometimes
// prepends the name of the Compose project to the name the user originally
// gave the network.
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

// containerNameMatches returns true if a canonical container name can
// be found from a combination of labels and names.
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
	// check if the Docker Compose service name matches
	if serviceName, ok := labels[composeServiceLabel]; ok && serviceName == expectedName {
		return true
	}

	return false
}

func buildChainName(name, id string) string {
	return fmt.Sprintf("%s%s-%s", chainPrefix, name, id[:12])
}

// createPortMappingRules adds nftables rules to allow or deny access to
// mapped ports.
func (r *RuleManager) createPortMappingRules(logger *zap.Logger, container types.ContainerJSON, contName string, mappedPortsCfg mappedPorts, addrs map[string][]byte, chain *nftables.Chain, nftRules []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule, error) {
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

	// prepend container name and ID to log prefixes
	if mappedPortsCfg.Localhost.LogPrefix != "" {
		mappedPortsCfg.Localhost.LogPrefix = formatLogPrefix(mappedPortsCfg.Localhost.LogPrefix, contName, container.ID)
	}
	if mappedPortsCfg.External.LogPrefix != "" {
		mappedPortsCfg.External.LogPrefix = formatLogPrefix(mappedPortsCfg.External.LogPrefix, contName, container.ID)
	}

	hostPortRules := make(map[uint16][]*nftables.Rule)
	for netName, netSettings := range container.NetworkSettings.Networks {
		gateway, err := netip.ParseAddr(netSettings.Gateway)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing gateway of network: %w", err)
		}

		// sort mapped ports so rules are created deterministically making
		// testing much easier
		ports := maps.Keys(container.NetworkSettings.Ports)
		slices.Sort(ports)

		for _, port := range ports {
			hostPorts := container.NetworkSettings.Ports[port]
			localAllowed := mappedPortsCfg.Localhost.Allow

			var proto protocol
			if err := proto.UnmarshalText([]byte(port.Proto())); err != nil {
				return nil, nil, fmt.Errorf("error parsing protocol: %w", err)
			}

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
					// create any rules
					continue
				}

				if !localAllowed || (localAllowed && (!mappedPortsCfg.External.Allow || mappedPortsCfg.External.IP.IsValid())) {
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
							LogPrefix: mappedPortsCfg.Localhost.LogPrefix,
							IP: addrOrRange{
								addr: gateway,
							},
							Proto:   proto,
							Port:    uint16(port.Int()),
							Verdict: mappedPortsCfg.Localhost.Verdict,
						},
						chain:  chain,
						contID: container.ID,
					}
					rule.cfg.Verdict.drop = !localAllowed
					nftRules = append(nftRules,
						r.createNFTRules(logger, rule)...,
					)
				}

				if !localAllowed {
					// Create rule to drop traffic going to the mapped
					// host port. This will prevent traffic originating
					// from localhost to be seen by Docker at all.
					hostPortInt, err := strconv.ParseUint(hostPort.HostPort, 10, 16)
					if err != nil {
						return nil, nil, fmt.Errorf("error parsing host port of port mapping: %w", err)
					}

					localhostDropRule := ruleDetails{
						inbound: true,
						cfg: ruleConfig{
							IP: addrOrRange{
								addr: localAddr,
							},
							Proto: proto,
							Port:  uint16(hostPortInt),
							Verdict: verdict{
								drop: true,
							},
						},
						chain:  whalewallChain,
						contID: container.ID,
					}
					nftRules = append(nftRules,
						r.createNFTRules(logger, localhostDropRule)...,
					)
				}
			}

			// if there are no host ports mapped to the container port,
			// don't create allow rules as the port wasn't exposed by
			// the user but rather was created from an EXPOSE Dockerfile
			// directive
			if mappedPortsCfg.External.Allow && len(hostPorts) > 0 {
				// create rules to allow external traffic to container
				rule := ruleDetails{
					inbound: true,
					addr:    addrs[netName],
					cfg: ruleConfig{
						LogPrefix: mappedPortsCfg.External.LogPrefix,
						IP:        mappedPortsCfg.External.IP,
						Proto:     proto,
						Port:      uint16(port.Int()),
						Verdict:   mappedPortsCfg.External.Verdict,
					},
					chain:  chain,
					contID: container.ID,
				}
				nftRules = append(nftRules,
					r.createNFTRules(logger, rule)...,
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

// createOutputRules adds nftables rules to allow outbound access from
// a container.
func (r *RuleManager) createOutputRules(ctx context.Context, logger *zap.Logger, ruleCfgs []ruleConfig, project string, addrs map[string][]byte, chain *nftables.Chain, name, id string, nftRules []*nftables.Rule) ([]*nftables.Rule, error) {
	for _, ruleCfg := range ruleCfgs {
		// prepend container name and ID to log prefixes
		if ruleCfg.LogPrefix != "" {
			ruleCfg.LogPrefix = formatLogPrefix(ruleCfg.LogPrefix, name, id)
		}

		rule := ruleDetails{
			inbound: false,
			cfg:     ruleCfg,
			chain:   chain,
			contID:  id,
		}

		if ruleCfg.Network != "" {
			_, addr, ok := findNetwork(ruleCfg.Network, project, addrs)
			if !ok {
				return nil, fmt.Errorf("network %q not found", ruleCfg.Network)
			}
			rule.addr = addr

			if ruleCfg.Container != "" {
				if ruleCfg.skip {
					// the container either hasn't been started yet or
					// doesn't exist; this rule will be created when
					// processing this container later
					continue
				}

				dstID, dstName, err := r.getContainerIDAndName(ctx, ruleCfg.Container)
				if err != nil {
					return nil, fmt.Errorf("error getting container %q ID from database: %w", ruleCfg.Container, err)
				}
				rule.estChain = &nftables.Chain{
					Table: filterTable,
					Name:  buildChainName(dstName, dstID),
				}
				rule.contID = dstID
				rule.estContID = id
			}

			nftRules = append(nftRules,
				r.createNFTRules(logger, rule)...,
			)
		} else {
			for _, addr := range addrs {
				rule.addr = addr
				nftRules = append(nftRules,
					r.createNFTRules(logger, rule)...,
				)
			}
		}
	}

	return nftRules, nil
}

// getContainerIDAndName returns the ID and canonical name of a container
// if it is present in the database.
func (r *RuleManager) getContainerIDAndName(ctx context.Context, contName string) (string, string, error) {
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

// createWaitingContainerRules creates nftables rules to allow access
// from another container to this container. The other container was
// processed before this container, so rules concerning this container
// couldn't be created until now.
func (r *RuleManager) createWaitingContainerRules(ctx context.Context, logger *zap.Logger, id, name, service, project string, addrs map[string][]byte, chain *nftables.Chain, estContainers map[string]struct{}, nftRules []*nftables.Rule) ([]*nftables.Rule, error) {
	var (
		waitingRules []database.GetWaitingContainerRulesRow
		err          error
		foundName    string
		aliases      = append([]string{name}, containerAliases(name, service)...)
	)

	for _, alias := range aliases {
		waitingRules, err = r.db.GetWaitingContainerRules(ctx, alias)
		if err != nil {
			return nil, fmt.Errorf("error getting waiting container rules of %q from database: %w", alias, err)
		}

		if len(waitingRules) == 0 {
			continue
		}
		foundName = alias
		break
	}
	if waitingRules == nil {
		return nftRules, nil
	}

	for _, waitingRule := range waitingRules {
		decoder := gob.NewDecoder(bytes.NewReader(waitingRule.Rule))
		var ruleCfg ruleConfig
		if err := decoder.Decode(&ruleCfg); err != nil {
			return nil, fmt.Errorf("error decoding waiting container rule: %w", err)
		}

		// find source container IP (not this container)
		srcCont, err := withTimeout(ctx, r.timeout, func(ctx context.Context) (types.ContainerJSON, error) {
			return r.dockerCli.ContainerInspect(ctx, waitingRule.SrcContainerID)
		})
		if err != nil {
			return nil, fmt.Errorf("error inspecting container %q: %w", waitingRule.Name, err)
		}
		srcProject := srcCont.Config.Labels[composeProjectLabel]
		srcNetName, srcNetwork, ok := findNetwork(ruleCfg.Network, srcProject, srcCont.NetworkSettings.Networks)
		if !ok {
			return nil, fmt.Errorf("network %q not found for container %q",
				ruleCfg.Network,
				ruleCfg.Container,
			)
		}
		srcAddr, err := netip.ParseAddr(srcNetwork.IPAddress)
		if err != nil {
			return nil, fmt.Errorf("error parsing IP of container %q from network %q: %w", ruleCfg.Container, srcNetName, err)
		}

		// find destination container IP (this container)
		dstNetName, dstNetwork, ok := findNetwork(ruleCfg.Network, project, addrs)
		if !ok {
			return nil, fmt.Errorf("network %q not found", ruleCfg.Network)
		}
		dstAddr, ok := netip.AddrFromSlice(dstNetwork)
		if !ok {
			return nil, fmt.Errorf("error parsing IP of from network %q", dstNetName)
		}
		ruleCfg.IP.addr = dstAddr

		// create rules
		rule := ruleDetails{
			inbound: false,
			addr:    ref(srcAddr.As4())[:],
			cfg:     ruleCfg,
			chain: &nftables.Chain{
				Table: filterTable,
				Name:  buildChainName(waitingRule.Name, waitingRule.SrcContainerID),
			},
			estChain:  chain,
			contID:    id,
			estContID: waitingRule.SrcContainerID,
		}
		nftRules = append(nftRules,
			r.createNFTRules(logger, rule)...,
		)
		estContainers[waitingRule.SrcContainerID] = struct{}{}
	}

	// deactivate waiting container rules so these rules are not created
	// again unless this container is restarted
	if err := r.db.DeactivateWaitingContainerRules(ctx, foundName); err != nil {
		return nil, fmt.Errorf("error updating waiting container rules from database: %w", err)
	}

	return nftRules, nil
}

func formatLogPrefix(prefix, name, id string) string {
	prefix = fmt.Sprintf("whalewall-%s-%s %s", name, id[:12], prefix)
	if !strings.HasSuffix(prefix, ": ") {
		prefix += ": "
	}

	return prefix
}

type ruleDetails struct {
	inbound   bool
	addr      []byte
	cfg       ruleConfig
	chain     *nftables.Chain
	estChain  *nftables.Chain
	contID    string
	estContID string
}

func (r ruleDetails) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("inbound", r.inbound)
	if len(r.addr) != 0 {
		ip, ok := netip.AddrFromSlice(r.addr)
		if !ok {
			return fmt.Errorf("error parsing addr %v", r.addr)
		}
		enc.AddString("container_addr", ip.String())
	}
	zap.Inline(r.cfg).AddTo(enc)
	if r.chain != nil {
		enc.AddString("chain", r.chain.Name)
	}
	if r.estChain != nil {
		enc.AddString("est_chain", r.estChain.Name)
	}
	enc.AddString("cont_id", r.contID)
	if r.estContID != "" {
		enc.AddString("est_cont_id", r.estContID)
	}

	return nil
}

// createNFTRules returns a slice of [*nftables.Rule] described by rd.
func (r *RuleManager) createNFTRules(logger *zap.Logger, rd ruleDetails) []*nftables.Rule {
	logger.Debug("creating rule", zap.Object("rule", rd))

	rules := make([]*nftables.Rule, 0, 3)
	estContID := rd.contID
	if rd.estChain == nil {
		rd.estChain = rd.chain
	} else {
		estContID = rd.estContID
	}

	// if the rule is a drop rule, only need to handle new traffic
	if rd.cfg.Verdict.drop {
		return append(rules,
			createNFTRule(rd.inbound, dstPortOffset, stateNew, rd.addr, rd.cfg, 0, rd.chain, rd.contID),
		)
	}

	if rd.cfg.Verdict.Queue == 0 {
		if rd.cfg.LogPrefix == "" {
			return append(rules,
				createNFTRule(rd.inbound, dstPortOffset, stateNewEst, rd.addr, rd.cfg, 0, rd.chain, rd.contID),
				createNFTRule(!rd.inbound, srcPortOffset, stateEst, rd.addr, rd.cfg, 0, rd.estChain, estContID),
			)
		}
		// create a separate rule for new traffic to log it
		return append(rules,
			createNFTRule(rd.inbound, dstPortOffset, stateNew, rd.addr, rd.cfg, 0, rd.chain, rd.contID),
			createNFTRule(rd.inbound, dstPortOffset, stateEst, rd.addr, rd.cfg, 0, rd.chain, rd.contID),
			createNFTRule(!rd.inbound, srcPortOffset, stateEst, rd.addr, rd.cfg, 0, rd.estChain, estContID),
		)
	}

	// If there is no log prefix set we can create one inbound rule and
	// one outbound rule in some situations. Otherwise new traffic must
	// be logged.
	if rd.cfg.LogPrefix == "" {
		if rd.inbound && rd.cfg.Verdict.Queue == rd.cfg.Verdict.InputEstQueue {
			// if rule is inbound and queue and established inbound queue
			// are the same, create one rule for inbound traffic
			return append(rules,
				createNFTRule(true, dstPortOffset, stateNewEst, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID),
				createNFTRule(false, srcPortOffset, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.OutputEstQueue, rd.estChain, estContID),
			)
		} else if !rd.inbound && rd.cfg.Verdict.Queue == rd.cfg.Verdict.OutputEstQueue {
			// if rule is outbound and queue and established outbound queue
			// are the same, create one rule for outbound traffic
			return append(rules,
				createNFTRule(false, dstPortOffset, stateNewEst, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID),
				createNFTRule(true, srcPortOffset, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.InputEstQueue, rd.estChain, estContID),
			)
		}
	}

	// if rule is inbound and queue and established inbound queue
	// are different, need to create separate rules for them;
	// or, logging was requested which means we need to create a
	// separate rule for new traffic
	if rd.inbound {
		return append(rules,
			createNFTRule(true, dstPortOffset, stateNew, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID),
			createNFTRule(true, dstPortOffset, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.InputEstQueue, rd.chain, rd.contID),
			createNFTRule(false, srcPortOffset, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.OutputEstQueue, rd.estChain, estContID),
		)
	}

	// if rule is outbound and queue and established outbound queue
	// are different, need to create separate rules for them;
	// or, logging was requested which means we need to create a
	// separate rule for new traffic
	return append(rules,
		createNFTRule(false, dstPortOffset, stateNew, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID),
		createNFTRule(false, dstPortOffset, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.OutputEstQueue, rd.chain, rd.contID),
		createNFTRule(true, srcPortOffset, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.InputEstQueue, rd.estChain, estContID),
	)
}

func createNFTRule(inbound bool, portOffset, state uint32, addr []byte, cfg ruleConfig, queueNum uint16, chain *nftables.Chain, contID string) *nftables.Rule {
	addrOffset := srcAddrOffset
	cfgAddrOffset := dstAddrOffset
	if inbound {
		addrOffset = dstAddrOffset
		cfgAddrOffset = srcAddrOffset
	}
	proto := unix.IPPROTO_TCP
	if cfg.Proto == udp {
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
			rangeExprs := matchIPRangeExprs(lowAddr, highAddr, cfgAddrOffset)
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
	if cfg.Proto != invalidProto {
		exprs = append(exprs, matchProtoExprs(proto)...)
	}
	if cfg.Port != 0 {
		exprs = append(exprs, matchPortExprs(cfg.Port, portOffset)...)
	}
	exprs = append(exprs, matchConnStateExprs(state)...)
	exprs = append(exprs, &expr.Counter{})
	if state == stateNew && cfg.LogPrefix != "" {
		exprs = append(exprs, logExpr(cfg.LogPrefix))
	}
	switch {
	case cfg.Verdict.Chain != "":
		exprs = append(exprs,
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: cfg.Verdict.Chain,
			},
		)
	case queueNum != 0:
		exprs = append(exprs,
			&expr.Queue{
				Num: queueNum,
			},
		)
	case cfg.Verdict.drop:
		exprs = append(exprs, dropVerdict)
	default:
		exprs = append(exprs, acceptVerdict)
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

func matchIPRangeExprs(lowAddr, highAddr netip.Addr, offset int) []expr.Any {
	return []expr.Any{
		// [ payload load 4b @ network header + ... => reg 1 ]
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			Len:           4,
			Base:          expr.PayloadBaseNetworkHeader,
			Offset:        uint32(offset),
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
}

func matchProtoExprs(proto int) []expr.Any {
	return []expr.Any{
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
	}
}

func matchPortExprs(port uint16, offset uint32) []expr.Any {
	return []expr.Any{
		// [ payload load 2b @ transport header + ... => reg 1 ]
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			Len:           2,
			Base:          expr.PayloadBaseTransportHeader,
			Offset:        offset,
			DestRegister:  1,
		},
		// [ cmp eq reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binary.BigEndian.AppendUint16(nil, port),
		},
	}
}

func matchConnStateExprs(state uint32) []expr.Any {
	return []expr.Any{
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
			Xor:            zeroUint32,
		},
		// [ cmp neq reg 1 0x00000000 ]
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     zeroUint32,
		},
	}
}

func logExpr(prefix string) expr.Any {
	return &expr.Log{
		Key:   (1 << unix.NFTA_LOG_PREFIX) | (1 << unix.NFTA_LOG_LEVEL),
		Level: expr.LogLevelInfo,
		Data:  []byte(prefix),
	}
}

func createDropRule(chain *nftables.Chain, id string) *nftables.Rule {
	return &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Counter{},
			logExpr(chain.Name + " drop: "),
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
		UserData: []byte(id),
	}
}

func ref[T any](v T) *T {
	return &v
}
