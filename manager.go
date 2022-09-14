package main

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"sync"

	"github.com/capnspacehook/whalewall/database"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/google/nftables"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

const (
	dbCommands = "PRAGMA busy_timeout = 1000;"

	enabledLabel = "whalewall.enabled"
	rulesLabel   = "whalewall.rules"
)

//go:embed database/schema.sql
var dbSchema string

type ruleManager struct {
	wg   sync.WaitGroup
	done chan struct{}

	db               *database.DB
	dockerCli        *client.Client
	nfc              *nftables.Conn
	chain            *nftables.Chain
	containerAddrSet *nftables.Set
}

func newRuleManager() *ruleManager {
	return &ruleManager{
		done: make(chan struct{}),
	}
}

func (r *ruleManager) start(ctx context.Context, dbFile string) error {
	if err := r.init(ctx, dbFile); err != nil {
		return err
	}
	if err := r.createBaseRules(); err != nil {
		return fmt.Errorf("error creating base rules: %v", err)
	}

	if err := r.cleanupRules(ctx); err != nil {
		log.Printf("error cleaning up rules: %v", err)
	}

	createChannel := make(chan types.ContainerJSON)
	deleteChannel := make(chan string)

	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		r.createRules(ctx, createChannel)
	}()
	go func() {
		defer r.wg.Done()
		r.deleteRules(ctx, deleteChannel)
	}()

	if err := r.syncContainers(ctx, createChannel); err != nil {
		log.Printf("error syncing containers: %v", err)
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		messages, streamErrs := addFilters(ctx, r.dockerCli)
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
						container, err := r.dockerCli.ContainerInspect(ctx, msg.ID)
						if err != nil {
							log.Printf("error inspecting container: %v", err)
							continue
						}
						createChannel <- container
					}
					if msg.Action == "kill" {
						deleteChannel <- msg.ID
					}
				}
			case err := <-streamErrs:
				// nil errors or context.Canceled will sometimes be sent
				// when the context is canceled, continue until the
				// manager is stopped
				if err == nil || errors.Is(err, context.Canceled) {
					continue
				}
				if !errors.Is(err, io.EOF) {
					log.Printf("error reading docker event stream: %v", err)
				}
				log.Println("recreating docker client")
				r.dockerCli, err = client.NewClientWithOpts(client.FromEnv)
				if err != nil {
					log.Fatalf("error creating docker client: %v", err)
				}
				messages, streamErrs = addFilters(ctx, r.dockerCli)
			case <-r.done:
				close(createChannel)
				close(deleteChannel)
				return
			}
		}
	}()

	return nil
}

func (r *ruleManager) init(ctx context.Context, dbFile string) error {
	var dbNotExist bool
	_, err := os.Stat(dbFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			dbNotExist = true
		} else {
			return err
		}
	}

	sqlDB, err := sql.Open("sqlite", dbFile)
	if err != nil {
		return fmt.Errorf("error opening database: %v", err)
	}
	// create database schema if a sqlite file doesn't exist
	if dbNotExist {
		if _, err := sqlDB.ExecContext(ctx, dbSchema); err != nil {
			return fmt.Errorf("error creating tables in database: %v", err)
		}
	}
	if _, err := sqlDB.ExecContext(ctx, dbCommands); err != nil {
		return fmt.Errorf("error executing commands in database: %v", err)
	}
	r.db, err = database.NewDB(ctx, sqlDB)
	if err != nil {
		return fmt.Errorf("error preparing database queries: %v", err)
	}

	r.dockerCli, err = client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("error creating docker client: %v", err)
	}
	c, err := nftables.New() // TODO: fix GetRules bug and make lasting
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %v", err)
	}
	r.nfc = c

	return nil
}

func addFilters(ctx context.Context, client *client.Client) (<-chan events.Message, <-chan error) {
	filter := filters.NewArgs(
		filters.KeyValuePair{
			Key:   "type",
			Value: "container",
		},
		filters.KeyValuePair{
			Key:   "event",
			Value: "start",
		},
		filters.KeyValuePair{
			Key:   "event",
			Value: "kill",
		},
	)
	return client.Events(ctx, types.EventsOptions{Filters: filter})
}

func (r *ruleManager) stop() {
	r.done <- struct{}{}
	r.wg.Wait()

	if err := r.dockerCli.Close(); err != nil {
		log.Printf("error closing docker client: %v", err)
	}
	if err := r.db.Close(); err != nil {
		log.Printf("error closing database: %v", err)
	}
}
