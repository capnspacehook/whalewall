package main

import (
	"bytes"
	"context"
	"log"

	"github.com/google/nftables"
)

func (r *ruleManager) deleteRules(ctx context.Context, containerID <-chan string) {
	for id := range containerID {
		name, err := r.db.GetContainerName(ctx, id)
		if err != nil {
			log.Printf("error getting name of container %s: %v", id, err)
			continue
		}
		addrs, err := r.db.GetContainerAddrs(ctx, id)
		if err != nil {
			log.Printf("error getting IPs of container %s: %v", id, err)
			continue
		}
		log.Printf("deleting rules of %q", name)

		// Handle inbound and outbound rules
		curRules, err := r.nfc.GetRules(r.chain.Table, r.chain)
		if err != nil {
			log.Printf("error getting rules of %q: %v", r.chain.Name, err)
			continue
		}
		idb := []byte(id)
		for i := range curRules {
			if bytes.Equal(idb, curRules[i].UserData) {
				r.nfc.DelRule(curRules[i])
			}
		}

		// Handle deny all out
		elements := make([]nftables.SetElement, len(addrs))
		for i, addr := range addrs {
			elements[i] = nftables.SetElement{
				Key: addr,
			}
		}
		err = r.nfc.SetDeleteElements(r.dropSet, elements)
		if err != nil {
			log.Printf("error deleting set elements: %v", err)
		}

		if err := r.nfc.Flush(); err != nil {
			log.Printf("error flushing nftables commands: %v", err)
			continue
		}

		r.deleteContainer(ctx, id)
	}
}
