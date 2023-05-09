package container

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

type Tracker struct {
	logger *zap.Logger
	mtx    sync.Mutex

	containers map[string]*processingContainer
}

type processingContainer struct {
	creating  bool
	cancel    context.CancelFunc
	noCleanup bool
	done      chan struct{}
}

func NewTracker(logger *zap.Logger) *Tracker {
	return &Tracker{
		logger:     logger,
		containers: make(map[string]*processingContainer),
	}
}

func (c *Tracker) StartCreatingContainer(ctx context.Context, id string) (context.Context, func()) {
	ctx, cleanup, _ := c.addContainer(ctx, id, true)
	return ctx, cleanup
}

func (c *Tracker) StartDeletingContainer(ctx context.Context, id string) (context.Context, func(), bool) {
	return c.addContainer(ctx, id, false)
}

func (c *Tracker) addContainer(ctx context.Context, id string, creating bool) (context.Context, func(), bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// if the same container is currently being processed, wait for it
	// to finish before starting a new operation on it
	cont, ok := c.containers[id]
	if ok {
		// we will reassign this map entry below, so prevent the cleanup
		// func from the current operation removing the new entry after
		// we return and the mutex unlocks
		cont.noCleanup = true

		// if the container is being created but will be deleted cancel
		// the current operation
		if cont.creating && !creating {
			c.logger.Debug("canceling container creation", zap.String("container.id", id[:12]))
			cont.cancel()
			delete(c.containers, id)
			return ctx, nil, false
		}

		c.logger.Debug("waiting on container operation to finish", zap.String("container.id", id[:12]), zap.Bool("container.creating", cont.creating))
		<-cont.done
	}

	ctx, cancel := context.WithCancel(ctx)
	newCont := &processingContainer{
		creating: creating,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	c.containers[id] = newCont

	return ctx, func() {
		newCont.cancel()
		close(newCont.done)

		c.mtx.Lock()
		defer c.mtx.Unlock()

		if newCont.noCleanup {
			return
		}
		delete(c.containers, id)
	}, true
}
