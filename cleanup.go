package main

import (
	"context"
	"fmt"
	"log"

	"github.com/docker/docker/client"
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
				r.deleteContainerRules(ctx, container.ID)
				continue
			} else {
				log.Printf("error inspecting container: %v", err)
				continue
			}
		}
		if !c.State.Running {
			log.Printf("cleaning rules of stopped container %s", container.Name)
			r.deleteContainerRules(ctx, container.ID)
		}
	}

	return nil
}
