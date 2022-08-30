package main

import (
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
		log.Printf("deleting rules of %q", c.Name)

		curRules, err := r.nfc.GetRules(r.chain.Table, r.chain)
		if err != nil {
			log.Printf("error getting rules of %q: %v", r.chain.Name, err)
			continue
		}

		// Handle inbound and outbound rules
		for i := range c.Rules {
			if findRule(c.Rules[i], curRules) {
				r.nfc.DelRule(c.Rules[i])
			}
		}

		// Handle deny all out
		elements := make([]nftables.SetElement, 0, len(c.Addrs))
		for _, addr := range c.Addrs {
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
