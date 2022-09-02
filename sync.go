package main

import (
	"context"
	"log"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"gopkg.in/yaml.v3"
)

func (r *ruleManager) syncContainers(ctx context.Context, createChannel chan types.ContainerJSON) {
	filter := filters.NewArgs(filters.KeyValuePair{
		Key:   "label",
		Value: enabledLabel,
	})
	containers, err := r.dockerCli.ContainerList(ctx, types.ContainerListOptions{Filters: filter})
	if err != nil {
		log.Println(err)
		return
	}

	for _, c := range containers {
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
}
