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
	containers, err := r.dockerCli.ContainerList(ctx, types.ContainerListOptions{Filters: filter})
	if err != nil {
		return fmt.Errorf("error listing containers: %w", err)
	}
	// sort containers so those that don't have dependencies go first
	slices.SortFunc(containers, func(a, b types.Container) bool {
		_, ok := a.Labels[composeDependsLabel]
		return ok
	})

	for _, c := range containers {
		truncID := c.ID[:12]
		container, err := r.dockerCli.ContainerInspect(ctx, c.ID)
		if err != nil {
			r.logger.Error("error inspecting container", zap.String("container.id", truncID), zap.Error(err))
			continue
		}

		exists, err := r.containerExists(ctx, r.db, c.ID)
		if err != nil {
			r.logger.Error("error querying container from database", zap.String("container.id", truncID), zap.Error(err))
			continue
		}
		if exists {
			// we are aware of the container and have created rules for
			// it before, but the rules could have been deleted since
			// then so recreate any missing rules
			r.createCh <- containerDetails{
				container: container,
				isNew:     false,
			}
			continue
		}

		enabled, err := whalewallEnabled(container.Config.Labels)
		if err != nil {
			r.logger.Error("error parsing label", zap.String("container.id", truncID), zap.String("label", enabledLabel), zap.Error(err))
			continue
		}
		if enabled {
			r.createCh <- containerDetails{
				container: container,
				isNew:     true,
			}
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
