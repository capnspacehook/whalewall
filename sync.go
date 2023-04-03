package whalewall

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

const composeDependsLabel = "com.docker.compose.depends_on"

func (r *RuleManager) syncContainers(ctx context.Context) error {
	filter := filters.NewArgs(filters.KeyValuePair{
		Key:   "label",
		Value: enabledLabel,
	})
	containers, err := withTimeout(ctx, r.timeout, func(ctx context.Context) ([]types.Container, error) {
		return r.dockerCli.ContainerList(ctx, types.ContainerListOptions{Filters: filter})
	})
	if err != nil {
		return fmt.Errorf("error listing containers: %w", err)
	}
	// sort containers so those that don't have dependencies go first
	slices.SortFunc(containers, func(a, b types.Container) bool {
		_, ok := a.Labels[composeDependsLabel]
		return ok
	})

	for _, c := range containers {
		exists, err := r.containerExists(ctx, c.ID)
		if err != nil {
			r.logger.Error("error querying container from database", zap.String("container.id", c.ID[:12]), zap.Error(err))
			continue
		}
		if exists {
			// we are aware of container and have created rules for it
			// TODO: should rules still try and be created, but container
			// not added to DB just in case some were deleted?
			continue
		}

		container, err := withTimeout(ctx, r.timeout, func(ctx context.Context) (types.ContainerJSON, error) {
			return r.dockerCli.ContainerInspect(ctx, c.ID)
		})
		if err != nil {
			r.logger.Error("error inspecting container", zap.String("container.id", c.ID[:12]), zap.Error(err))
			continue
		}

		enabled, err := whalewallEnabled(container.Config.Labels)
		if err != nil {
			r.logger.Error("error parsing label", zap.String("container.id", c.ID[:12]), zap.String("label", enabledLabel), zap.Error(err))
			continue
		}
		if enabled {
			r.createCh <- container
		}
	}

	return nil
}

func whalewallEnabled(labels map[string]string) (bool, error) {
	e, ok := labels[enabledLabel]
	if !ok {
		return false, nil
	}

	var enabled bool
	if err := yaml.Unmarshal([]byte(e), &enabled); err != nil {
		return false, err
	}

	return enabled, nil
}
