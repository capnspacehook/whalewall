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
		log.Printf("deleting rules of %q", c.name)

		delete := func(natTable bool) bool {
			chain := r.filterChain
			rules := c.filterRules
			set := r.filterDropSet
			if natTable {
				chain = r.natChain
				rules = c.natRules
				set = r.natDropSet
			}

			// Handle inbound and outbound rules
			curRules, err := r.nfc.GetRules(chain.Table, chain)
			if err != nil {
				log.Printf("error getting rules of %q: %v", chain.Name, err)
				return false
			}
			for i := range rules {
				if findRule(rules[i], curRules) {
					r.nfc.DelRule(rules[i])
				}
			}

			// Handle deny all out
			elements := make([]nftables.SetElement, 0, len(c.addrs))
			for _, addr := range c.addrs {
				elements = append(elements, nftables.SetElement{
					Key: addr,
				})
			}
			err = r.nfc.SetDeleteElements(set, elements)
			if err != nil {
				log.Printf("error deleting set elements: %v", err)
			}

			return true
		}

		if !delete(false) {
			continue
		}
		if !delete(true) {
			continue
		}

		if err := r.nfc.Flush(); err != nil {
			log.Printf("error flushing commands: %v", err)
			continue
		}

		r.deleteContainer(id)
	}
}
