package main

import (
	"context"
	"fmt"
	"log"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"gopkg.in/yaml.v3"
)

func (r *ruleManager) syncContainers(ctx context.Context, createChannel chan types.ContainerJSON) error {
	filter := filters.NewArgs(filters.KeyValuePair{
		Key:   "label",
		Value: enabledLabel,
	})
	containers, err := r.dockerCli.ContainerList(ctx, types.ContainerListOptions{Filters: filter})
	if err != nil {
		return fmt.Errorf("error listing containers: %v", err)
	}

	for _, c := range containers {
		e, err := r.db.ContainerExists(ctx, c.ID)
		if err != nil {
			log.Printf("error querying container %q from database: %v", c.ID, err)
			continue
		}
		exists, ok := e.(int64)
		if !ok {
			return fmt.Errorf("got unexpected type from SQL query: %T", e)
		}
		if exists == 1 {
			// we are aware of container and have created rules for it
			// TODO: should rules still try and be created, but container
			// not added to DB just in case some were deleted?
			continue
		}

		container, err := r.dockerCli.ContainerInspect(ctx, c.ID)
		if err != nil {
			log.Printf("error inspecting container: %v", err)
			continue
		}

		if e, ok := container.Config.Labels[enabledLabel]; ok {
			var enabled bool
			if err := yaml.Unmarshal([]byte(e), &enabled); err != nil {
				log.Printf("error parsing %q label: %v", enabledLabel, err)
				continue
			}
			if enabled {
				createChannel <- container
			}
		}
	}

	return nil
}
