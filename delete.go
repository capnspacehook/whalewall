package main

import (
	"bytes"
	"context"
	"errors"
	"syscall"

	"github.com/google/nftables"
	"go.uber.org/zap"
)

func (r *ruleManager) deleteRules(ctx context.Context) {
	for id := range r.deleteCh {
		name, err := r.db.GetContainerName(ctx, id)
		if err != nil {
			r.logger.Error("error getting name of container", zap.String("container.id", id[:12]), zap.Error(err))
			continue
		}
		r.logger.Info("deleting rules", zap.String("container.id", id[:12]), zap.String("container.name", name))

		r.deleteContainerRules(ctx, id, name)
	}
}

func (r *ruleManager) deleteContainerRules(ctx context.Context, id, name string) {
	logger := r.logger.With(zap.String("container.id", id[:12]), zap.String("container.name", name))
	rules, err := r.nfc.GetRules(r.chain.Table, r.chain)
	if err != nil {
		logger.Error("error getting rules of chain", zap.String("chain.name", r.chain.Name), zap.Error(err))
		return
	}

	r.deleteRulesOfChain(logger, rules, id)

	addrs, err := r.db.GetContainerAddrs(ctx, id)
	if err != nil {
		logger.Error("error getting container addrs", zap.Error(err))
		return
	}

	for _, addr := range addrs {
		e := []nftables.SetElement{{Key: addr}}
		if err := r.nfc.SetDeleteElements(r.containerAddrSet, e); err != nil {
			logger.Error("error marshalling set elements", zap.Error(err))
			continue
		}
		// flush after every element deletion to ensure all possible
		// elements are deleted
		err = r.nfc.Flush()
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
			Table: r.chain.Table,
			Name:  buildChainName(estCont.Name, estCont.DstContainerID),
		}
		rules, err := r.nfc.GetRules(chain.Table, chain)
		if err != nil {
			logger.Error("error getting rules of chain", zap.String("chain.name", chain.Name), zap.Error(err))
			continue
		}
		r.deleteRulesOfChain(logger, rules, id)
	}

	chainName := buildChainName(name, id)
	r.nfc.DelChain(&nftables.Chain{
		Table: r.chain.Table,
		Name:  chainName,
	})
	err = r.nfc.Flush()
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		logger.Error("error deleting chain", zap.String("chain.name", chainName), zap.Error(err))
	}

	if err := r.deleteContainer(ctx, logger, id); err != nil {
		logger.Error("error deleting container from database", zap.Error(err))
	}
}

func (r *ruleManager) deleteRulesOfChain(logger *zap.Logger, rules []*nftables.Rule, id string) {
	idb := []byte(id)
	for _, rule := range rules {
		if !bytes.Equal(idb, rule.UserData) {
			continue
		}

		r.nfc.DelRule(rule)
		// flush after every rule deletion to ensure all possible
		// rules are deleted
		err := r.nfc.Flush()
		if err != nil && !errors.Is(err, syscall.ENOENT) {
			logger.Error("error deleting rule", zap.Error(err))
		}
	}
}
