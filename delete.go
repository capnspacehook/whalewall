package whalewall

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"syscall"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/google/nftables"
	"go.uber.org/zap"
)

// clear initializes the database and removes all nftables rules created
// by whalewall.
func (r *RuleManager) Clear(ctx context.Context, dbFile string) error {
	if err := r.initDB(ctx, dbFile); err != nil {
		return err
	}

	return r.clearRules(ctx)
}

// clearRules removes all nftables rules created by whalewall.
func (r *RuleManager) clearRules(ctx context.Context) error {
	// delete container chains
	containers, err := r.db.GetContainers(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("error getting containers from database: %w", err)
	}
	for _, container := range containers {
		truncID := container.ID[:12]
		r.logger.Info("deleting rules", zap.String("container.id", truncID), zap.String("container.name", container.Name))
		r.deleteContainerRules(ctx, container.ID, container.Name)
	}

	nfc, err := r.newFirewallClient()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}

	// delete jump rules to whalewall chain
	for _, chainName := range []string{dockerChainName, inputChainName, outputChainName} {
		chain := &nftables.Chain{
			Name:  chainName,
			Table: filterTable,
		}
		rules, err := nfc.GetRules(filterTable, chain)
		if err != nil {
			r.logger.Error("error getting rules of chain", zap.String("chain.name", chainName), zap.Error(err))
			continue
		}

		jumpRule := createJumpRule(chain, whalewallChainName)
		if findRule(r.logger, jumpRule, rules) {
			if err := nfc.DelRule(jumpRule); err != nil {
				r.logger.Error("error deleting rule", zap.Error(err))
				continue
			}
			err = nfc.Flush()
			if err != nil && !errors.Is(err, syscall.ENOENT) {
				r.logger.Error("error deleting rule from chain", zap.String("chain.name", chainName), zap.Error(err))
			}
		}
	}

	// delete whalewall chain
	nfc.DelChain(whalewallChain)
	err = nfc.Flush()
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("error deleting chain %q: %w", whalewallChainName, err)
	}

	// delete container address set
	nfc.DelSet(containerAddrSet)
	err = nfc.Flush()
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("error deleting set %q: %w", containerAddrSetName, err)
	}

	return nil
}

// cleanupRules removes nftables rules for containers that are now
// stopped or were removed.
func (r *RuleManager) cleanupRules(ctx context.Context) error {
	containers, err := r.db.GetContainers(ctx)
	if err != nil {
		return fmt.Errorf("error getting containers from database: %w", err)
	}

	for _, container := range containers {
		c, err := withTimeout(ctx, r.timeout, func(ctx context.Context) (types.ContainerJSON, error) {
			return r.dockerCli.ContainerInspect(ctx, container.ID)
		})
		if err != nil {
			if client.IsErrNotFound(err) {
				contName := stripName(container.Name)
				r.logger.Info("cleaning rules of removed container", zap.String("container.id", container.ID[:12]), zap.String("container.name", contName))
				r.deleteContainerRules(ctx, container.ID, contName)
				continue
			} else {
				r.logger.Error("error inspecting container: %w", zap.Error(err))
				continue
			}
		}
		if !c.State.Running {
			contName := stripName(container.Name)
			r.logger.Info("cleaning rules of stopped container", zap.String("container.id", container.ID[:12]), zap.String("container.name", contName))
			r.deleteContainerRules(ctx, container.ID, contName)
		}
	}

	return nil
}

// deleteRules removes nftables rules for stopped or killed containers.
func (r *RuleManager) deleteRules(ctx context.Context) {
	for id := range r.deleteCh {
		name, err := r.db.GetContainerName(ctx, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// container is not in database, most likely an error was
				// encountered when creating rules for it
				continue
			}
			r.logger.Error("error getting name of container", zap.String("container.id", id[:12]), zap.Error(err))
			continue
		}

		r.logger.Info("deleting rules", zap.String("container.id", id[:12]), zap.String("container.name", name))
		r.deleteContainerRules(ctx, id, name)
	}
}

// deleteContainerRules removes all nftables rules for a container.
func (r *RuleManager) deleteContainerRules(ctx context.Context, id, name string) {
	logger := r.logger.With(zap.String("container.id", id[:12]), zap.String("container.name", name))
	nfc, err := r.newFirewallClient()
	if err != nil {
		logger.Error("error creating netlink connection", zap.Error(err))
		return
	}

	// delete rules from whalewall chain
	rules, err := nfc.GetRules(filterTable, whalewallChain)
	if err != nil {
		logger.Error("error getting rules of chain", zap.String("chain.name", whalewallChain.Name), zap.Error(err))
		return
	}

	deleteRulesFromContainer(logger, nfc, rules, id)

	addrs, err := r.db.GetContainerAddrs(ctx, id)
	if err != nil {
		logger.Error("error getting container addrs", zap.Error(err))
		return
	}

	for _, addr := range addrs {
		e := []nftables.SetElement{{Key: addr}}
		if err := nfc.SetDeleteElements(containerAddrSet, e); err != nil {
			logger.Error("error marshaling set elements", zap.Error(err))
			continue
		}
		// flush after every element deletion to ensure all possible
		// elements are deleted
		err = nfc.Flush()
		if err != nil && !errors.Is(err, syscall.ENOENT) {
			logger.Error("error deleting set element", zap.Error(err))
		}
	}

	estContainers, err := r.db.GetEstContainers(ctx, id)
	if err != nil {
		logger.Error("error getting established containers", zap.Error(err))
		return
	}

	// delete rules in other container's chains
	for _, estCont := range estContainers {
		chain := &nftables.Chain{
			Table: filterTable,
			Name:  buildChainName(estCont.Name, estCont.DstContainerID),
		}
		rules, err := nfc.GetRules(chain.Table, chain)
		if err != nil {
			logger.Error("error getting rules of chain", zap.String("chain.name", chain.Name), zap.Error(err))
			continue
		}
		deleteRulesFromContainer(logger, nfc, rules, id)
	}

	// delete container chain
	chainName := buildChainName(name, id)
	nfc.DelChain(&nftables.Chain{
		Table: filterTable,
		Name:  chainName,
	})
	err = nfc.Flush()
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		logger.Error("error deleting chain", zap.String("chain.name", chainName), zap.Error(err))
	}

	logger.Debug("deleting from database")
	if err := r.deleteContainer(ctx, logger, id); err != nil {
		logger.Error("error deleting container from database", zap.Error(err))
	}
}

// deleteRulesFromContainer removes nftables rules that belong to a container
// specified by id.
func deleteRulesFromContainer(logger *zap.Logger, nfc firewallClient, rules []*nftables.Rule, id string) {
	idb := []byte(id)
	for _, rule := range rules {
		if !bytes.Equal(idb, rule.UserData) {
			continue
		}

		if err := nfc.DelRule(rule); err != nil {
			logger.Error("error deleting rule", zap.Error(err))
			continue
		}
		// flush after every rule deletion to ensure all possible
		// rules are deleted
		err := nfc.Flush()
		if err != nil && !errors.Is(err, syscall.ENOENT) {
			logger.Error("error deleting rule", zap.Error(err))
		}
	}
}
