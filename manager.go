package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/google/nftables"
	"gopkg.in/yaml.v3"
)

const (
	enabledLabel = "whalewall.enabled"
	rulesLabel   = "whalewall.rules"
)

type ruleManager struct {
	mtx  sync.RWMutex
	wg   sync.WaitGroup
	done chan struct{}

	nfc        *nftables.Conn
	chain      *nftables.Chain
	dropSet    *nftables.Set
	containers map[string]*containerInfo
}

type containerInfo struct {
	Name  string
	Addrs map[string][]byte
	Cfg   containerRules
	Rules []*nftables.Rule
}

func newRuleManager() *ruleManager {
	return &ruleManager{
		done:       make(chan struct{}),
		containers: make(map[string]*containerInfo),
	}
}

func (r *ruleManager) start(ctx context.Context) error {
	dockerCli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("error creating docker client: %v", err)
	}
	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %v", err)
	}
	r.nfc = c

	if err := r.createBaseRules(); err != nil {
		return fmt.Errorf("error creating base rules: %v", err)
	}

	createChannel := make(chan *types.ContainerJSON)
	deleteChannel := make(chan string)

	// TODO: make "2"
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.createRules(createChannel)
	}()
	// go func() {
	// 	defer r.wg.Done()
	// 	r.deleteUFWRules(deleteChannel)
	// }()

	syncContainers(ctx, createChannel, dockerCli)
	//cleanupRules(ctx, dockerCli)

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		messages, streamErrs := addFilters(ctx, dockerCli)
		for {
			select {
			case msg := <-messages:
				if e, ok := msg.Actor.Attributes[enabledLabel]; ok {
					var enabled bool
					if err := yaml.Unmarshal([]byte(e), &enabled); err != nil {
						log.Printf("error parsing %q label: %v", enabledLabel, err)
						continue
					}
					if !enabled {
						continue
					}

					if msg.Action == "start" {
						// if no rules are defined there is nothing to be done
						if _, ok := msg.Actor.Attributes[rulesLabel]; !ok {
							continue
						}

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
				if errors.Is(err, context.Canceled) {
					continue
				}
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

	r.nfc.CloseLasting()
}

func (r *ruleManager) addContainer(id string, container *containerInfo) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	r.containers[id] = container
}

func (r *ruleManager) getContainer(id string) (*containerInfo, bool) {
	r.mtx.RLock()
	defer r.mtx.RUnlock()

	c, ok := r.containers[id]
	return c, ok
}
