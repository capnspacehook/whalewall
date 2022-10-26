package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"syscall"

	"github.com/google/nftables"
	"go.uber.org/zap"
)

func (r *ruleManager) deleteRules(ctx context.Context) {
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

func (r *ruleManager) deleteContainerRules(ctx context.Context, id, name string) {
	logger := r.logger.With(zap.String("container.id", id[:12]), zap.String("container.name", name))
	nfc, err := nftables.New()
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

	deleteRulesOfChain(logger, nfc, rules, id)

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
		deleteRulesOfChain(logger, nfc, rules, id)
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

func deleteRulesOfChain(logger *zap.Logger, nfc *nftables.Conn, rules []*nftables.Rule, id string) {
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
