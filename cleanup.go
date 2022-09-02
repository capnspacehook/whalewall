package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/docker/docker/client"
	"github.com/google/nftables"
)

func (r *ruleManager) cleanupRules(ctx context.Context) error {
	containers, err := r.db.GetContainers(ctx)
	if err != nil {
		return fmt.Errorf("error getting containers from database: %v", err)
	}

	for _, container := range containers {
		c, err := r.dockerCli.ContainerInspect(ctx, container.ID)
		if err != nil {
			if client.IsErrNotFound(err) {
				log.Printf("cleaning rules of removed container %s", container.Name)
				r.clean(ctx, container.ID)
				continue
			} else {
				log.Printf("error inspecting container: %v", err)
				continue
			}
		}
		if !c.State.Running {
			log.Printf("cleaning rules of stopped container %s", container.Name)
			r.clean(ctx, container.ID)
		}
	}

	return nil
}

func (r *ruleManager) clean(ctx context.Context, id string) {
	rules, err := r.nfc.GetRules(r.chain.Table, r.chain)
	if err != nil {
		log.Printf("error getting rules of chain %q: %v", r.chain.Name, err)
		return
	}
	idb := []byte(id)
	for _, rule := range rules {
		if bytes.Equal(idb, rule.UserData) {
			r.nfc.DelRule(rule)
		}
	}

	addrs, err := r.db.GetContainerAddrs(ctx, id)
	if err != nil {
		log.Printf("error getting container addrs: %v", err)
		return
	}

	elements := make([]nftables.SetElement, len(addrs))
	for i, addr := range addrs {
		elements[i] = nftables.SetElement{
			Key: addr,
		}
	}
	if err := r.nfc.SetDeleteElements(r.dropSet, elements); err != nil {
		log.Printf("error deleting set elements: %v", err)
		return
	}

	if err := r.nfc.Flush(); err != nil {
		log.Printf("error flushing nftables commands: %v", err)
		return
	}

	r.deleteContainer(ctx, id)
}
