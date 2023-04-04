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

// withTimeout runs f with a timeout derived from [context.WithTimeout].
// Using withTimeout guarantees that:
//
//   - ctx is only shadowed in withTimeout's scope
//   - The child context will have it's resources released immediately
//     after f returns
//
// The main goal of withTimeout is to prevent shadowing ctx with a
// context with a timeout, having that timeout expire and the next call
// that uses ctx immediately fail.
func withTimeout[T, E any](ctx context.Context, timeout time.Duration, f func(ctx context.Context) (T, E)) (T, E) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return f(ctx)
}
