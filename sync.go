package main

import (
	"context"
	"log"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

func syncContainers(ctx context.Context, createChannel chan *types.ContainerJSON, client *client.Client) {
	var filter = filters.NewArgs()
	filter.Add("label", "UFW_MANAGED=TRUE")
	containers, err := client.ContainerList(ctx, types.ContainerListOptions{Filters: filter})
	if err != nil {
		log.Println(err)
	}

	for _, c := range containers {
		container, err := client.ContainerInspect(ctx, c.ID)
		if err != nil {
			log.Printf("error inspecting container: %v", err)
			continue
		}
		createChannel <- &container
	}
}
