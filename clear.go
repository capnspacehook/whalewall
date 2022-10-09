package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"syscall"

	"github.com/google/nftables"
	"go.uber.org/zap"
)

func (r *ruleManager) clear(ctx context.Context, dataDir string) error {
	if err := r.initDB(ctx, dataDir); err != nil {
		return err
	}

	return r.clearRules(ctx)
}

func (r *ruleManager) clearRules(ctx context.Context) error {
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

	nfc, err := nftables.New()
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
			nfc.DelRule(jumpRule)
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
