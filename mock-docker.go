package whalewall

import (
	"context"
	"errors"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"golang.org/x/exp/slices"
)

type dockerClient interface {
	Ping(ctx context.Context) (types.Ping, error)
	Events(ctx context.Context, options types.EventsOptions) (<-chan events.Message, <-chan error)
	ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error)
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
	Close() error
}

type mockDockerClient struct {
	mtx sync.RWMutex

	eventCh    chan events.Message
	containers []types.ContainerJSON
}

func newMockDockerClient(containers []types.ContainerJSON) *mockDockerClient {
	return &mockDockerClient{
		eventCh:    make(chan events.Message),
		containers: containers,
	}
}

func (m *mockDockerClient) Ping(_ context.Context) (types.Ping, error) {
	return types.Ping{}, nil
}

func (m *mockDockerClient) Events(_ context.Context, _ types.EventsOptions) (<-chan events.Message, <-chan error) {
	return m.eventCh, nil
}

func (m *mockDockerClient) ContainerList(_ context.Context, _ types.ContainerListOptions) ([]types.Container, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	listedConts := make([]types.Container, len(m.containers))
	for i, cont := range m.containers {
		listedConts[i] = types.Container{
			ID:     cont.ID,
			Names:  []string{cont.Name},
			Labels: cont.Config.Labels,
		}
	}

	return listedConts, nil
}

func (m *mockDockerClient) ContainerInspect(_ context.Context, containerID string) (types.ContainerJSON, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	i := slices.IndexFunc(m.containers, func(c types.ContainerJSON) bool {
		return c.ID == containerID
	})
	if i == -1 {
		return types.ContainerJSON{}, errors.New("container not found")
	}

	return m.containers[i], nil
}

func (m *mockDockerClient) Close() error {
	return nil
}
