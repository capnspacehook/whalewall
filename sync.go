package main

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func (r *ruleManager) syncContainers(ctx context.Context) error {
	filter := filters.NewArgs(filters.KeyValuePair{
		Key:   "label",
		Value: enabledLabel,
	})
	containers, err := r.dockerCli.ContainerList(ctx, types.ContainerListOptions{Filters: filter})
	if err != nil {
		return fmt.Errorf("error listing containers: %w", err)
	}

	for _, c := range containers {
		e, err := r.db.ContainerExists(ctx, c.ID)
		if err != nil {
			r.logger.Error("error querying container from database", zap.String("container.id", c.ID), zap.Error(err))
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
			r.logger.Error("error inspecting container", zap.String("container.id", c.ID), zap.Error(err))
			continue
		}

		if e, ok := container.Config.Labels[enabledLabel]; ok {
			var enabled bool
			if err := yaml.Unmarshal([]byte(e), &enabled); err != nil {
				r.logger.Error("error parsing label", zap.String("label", enabledLabel), zap.Error(err))
				continue
			}
			if enabled {
				r.createCh <- container
			}
		}
	}

	return nil
}
