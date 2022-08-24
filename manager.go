package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

type ruleManager struct {
	mtx        sync.RWMutex
	wg         sync.WaitGroup
	done       chan struct{}
	containers map[string]*containerRules
}

type containerRules struct {
	Name             string
	IPAddress        string
	Labels           map[string]string
	UfwInboundRules  []ufwRule
	UfwOutboundRules []ufwRule
}

type ufwRule struct {
	CIDR    string
	Port    string
	Proto   string
	Comment string
}

func newRuleManager() *ruleManager {
	return &ruleManager{
		done:       make(chan struct{}),
		containers: make(map[string]*containerRules),
	}
}

func (r *ruleManager) start(ctx context.Context) error {
	dockerCli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("error creating docker client: %v", err)
	}

	createChannel := make(chan *types.ContainerJSON)
	deleteChannel := make(chan string)

	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		r.createUFWRules(createChannel)
	}()
	go func() {
		defer r.wg.Done()
		r.deleteUFWRules(deleteChannel)
	}()

	syncContainers(ctx, createChannel, dockerCli)
	cleanupRules(ctx, dockerCli)

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		messages, streamErrs := addFilters(ctx, dockerCli)
		for {
			select {
			case msg := <-messages:
				if ufwManaged := msg.Actor.Attributes["UFW_MANAGED"]; strings.ToUpper(ufwManaged) == "TRUE" {
					if msg.Action == "start" {
						container, err := dockerCli.ContainerInspect(ctx, msg.ID)
						if err != nil {
							log.Printf("error inspecting container: %v", err)
							continue
						}
						createChannel <- &container
					}
					if msg.Action == "kill" {
						deleteChannel <- msg.ID[:12]
					}
				}
			case err := <-streamErrs:
				if !errors.Is(err, io.EOF) {
					log.Printf("error reading docker event stream: %v", err)
				}
				log.Println("recreating docker client")
				dockerCli, err = client.NewClientWithOpts(client.FromEnv)
				if err != nil {
					log.Fatalf("error creating docker client: %v", err)
				}
				messages, streamErrs = addFilters(ctx, dockerCli)
			case <-r.done:
				close(createChannel)
				close(deleteChannel)
				return
			}
		}
	}()

	return nil
}

func addFilters(ctx context.Context, client *client.Client) (<-chan events.Message, <-chan error) {
	filter := filters.NewArgs()
	filter.Add("type", "container")
	return client.Events(ctx, types.EventsOptions{Filters: filter})
}

func (r *ruleManager) stop() {
	r.done <- struct{}{}
	r.wg.Wait()
}

func (r *ruleManager) addContainer(id string, container *containerRules) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	r.containers[id] = container
}

func (r *ruleManager) getContainer(id string) (*containerRules, bool) {
	r.mtx.RLock()
	defer r.mtx.RUnlock()

	c, ok := r.containers[id]
	return c, ok
}
