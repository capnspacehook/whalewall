package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"syscall"

	"github.com/google/nftables"
)

func (r *ruleManager) deleteRules(ctx context.Context) {
	for id := range r.deleteCh {
		name, err := r.db.GetContainerName(ctx, id)
		if err != nil {
			log.Printf("error getting name of container %s: %v", id, err)
			continue
		}
		log.Printf("deleting rules of %q", name)

		r.deleteContainerRules(ctx, id)
	}
}

func (r *ruleManager) deleteContainerRules(ctx context.Context, id string) {
	rules, err := r.nfc.GetRules(r.chain.Table, r.chain)
	if err != nil {
		log.Printf("error getting rules of chain %q: %v", r.chain.Name, err)
		return
	}

	idb := []byte(id)
	for _, rule := range rules {
		if bytes.Equal(idb, rule.UserData) {
			r.nfc.DelRule(rule)
			// flush after every rule deletion to ensure all possible
			// rules are deleted
			err = r.nfc.Flush()
			if err != nil && !errors.Is(err, syscall.ENOENT) {
				log.Printf("error deleting rule: %v", err)
			}
		}
	}

	addrs, err := r.db.GetContainerAddrs(ctx, id)
	if err != nil {
		log.Printf("error getting container addrs: %v", err)
		return
	}

	for _, addr := range addrs {
		e := []nftables.SetElement{{Key: addr}}
		if err := r.nfc.SetDeleteElements(r.containerAddrSet, e); err != nil {
			log.Printf("error marshalling set elements: %v", err)
			continue
		}
		// flush after every element deletion to ensure all possible
		// elements are deleted
		err = r.nfc.Flush()
		if err != nil && !errors.Is(err, syscall.ENOENT) {
			log.Printf("error deleting set element: %v", err)
		}
	}

	name, err := r.db.GetContainerName(ctx, id)
	if err != nil {
		log.Printf("error getting container name: %v", err)
		return
	}

	r.nfc.DelChain(&nftables.Chain{
		Table: r.chain.Table,
		Name:  buildChainName(name, id),
	})
	err = r.nfc.Flush()
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		log.Printf("error deleting chain: %v", err)
	}

	r.deleteContainer(ctx, id)
}
