package main

import (
	"bytes"
	"log"

	"github.com/google/nftables"
)

func (r *ruleManager) deleteRules(containerID <-chan string) {
	for id := range containerID {
		c, ok := r.getContainer(id)
		if !ok {
			log.Printf("container %s not found", id)
			continue
		}
		log.Printf("deleting rules of %q", c.name)

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
		elements := make([]nftables.SetElement, 0, len(c.addrs))
		for _, addr := range c.addrs {
			elements = append(elements, nftables.SetElement{
				Key: addr,
			})
		}
		err = r.nfc.SetDeleteElements(r.dropSet, elements)
		if err != nil {
			log.Printf("error deleting set elements: %v", err)
		}

		if err := r.nfc.Flush(); err != nil {
			log.Printf("error flushing commands: %v", err)
			continue
		}

		r.deleteContainer(id)
	}
}
