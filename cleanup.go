package main

import (
	"context"
	"fmt"

	"github.com/docker/docker/client"
	"go.uber.org/zap"
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
				contName := stripName(container.Name)
				r.logger.Info("cleaning rules of removed container", zap.String("container.id", container.ID[:12]), zap.String("container.name", contName))
				r.deleteContainerRules(ctx, container.ID, contName)
				continue
			} else {
				r.logger.Error("error inspecting container: %v", zap.Error(err))
				continue
			}
		}
		if !c.State.Running {
			contName := stripName(container.Name)
			r.logger.Info("cleaning rules of stopped container", zap.String("container.id", container.ID[:12]), zap.String("container.name", contName))
			r.deleteContainerRules(ctx, container.ID, stripName(container.Name))
		}
	}

	return nil
}
