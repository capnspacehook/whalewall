package main

import (
	"context"
	"log"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"gopkg.in/yaml.v3"
)

func syncContainers(ctx context.Context, createChannel chan types.ContainerJSON, client *client.Client) {
	filter := filters.NewArgs(filters.KeyValuePair{
		Key:   "label",
		Value: enabledLabel,
	})
	containers, err := client.ContainerList(ctx, types.ContainerListOptions{Filters: filter})
	if err != nil {
		log.Println(err)
		return
	}

	for _, c := range containers {
		container, err := client.ContainerInspect(ctx, c.ID)
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
