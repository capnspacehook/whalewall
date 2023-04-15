package whalewall

import (
	"context"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
)

// wrappedDockerClient is a Docker client that respects the set timeout.
type wrappedDockerClient struct {
	timeout time.Duration
	dockerClient
}

func (w *wrappedDockerClient) Ping(ctx context.Context) (types.Ping, error) {
	return withTimeout(ctx, w.timeout, func(ctx context.Context) (types.Ping, error) {
		return w.dockerClient.Ping(ctx)
	})
}

func (w *wrappedDockerClient) Events(ctx context.Context, options types.EventsOptions) (<-chan events.Message, <-chan error) {
	return withTimeout(ctx, w.timeout, func(ctx context.Context) (<-chan events.Message, <-chan error) {
		return w.dockerClient.Events(ctx, options)
	})
}

func (w *wrappedDockerClient) ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error) {
	return withTimeout(ctx, w.timeout, func(ctx context.Context) ([]types.Container, error) {
		return w.dockerClient.ContainerList(ctx, options)
	})
}

func (w *wrappedDockerClient) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	return withTimeout(ctx, w.timeout, func(ctx context.Context) (types.ContainerJSON, error) {
		return w.dockerClient.ContainerInspect(ctx, containerID)
	})
}
