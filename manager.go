package main

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/google/nftables"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"github.com/capnspacehook/whalewall/database"
)

const (
	dbCommands = `
PRAGMA busy_timeout = 1000;
PRAGMA journal_mode=WAL;
`

	enabledLabel = "whalewall.enabled"
	rulesLabel   = "whalewall.rules"
)

//go:embed database/schema.sql
var dbSchema string

type ruleManager struct {
	wg   sync.WaitGroup
	done chan struct{}

	logger *zap.Logger

	createCh chan types.ContainerJSON
	deleteCh chan string

	db        *database.DB
	dockerCli *client.Client

	chain            *nftables.Chain
	containerAddrSet *nftables.Set
}

func newRuleManager(logger *zap.Logger) *ruleManager {
	return &ruleManager{
		done:   make(chan struct{}),
		logger: logger,
	}
}

func (r *ruleManager) start(ctx context.Context, dbFile string) error {
	if err := r.init(ctx, dbFile); err != nil {
		return err
	}
	if err := r.createBaseRules(); err != nil {
		return fmt.Errorf("error creating base rules: %w", err)
	}

	if err := r.cleanupRules(ctx); err != nil {
		r.logger.Error("error cleaning up rules", zap.Error(err))
	}

	r.createCh = make(chan types.ContainerJSON)
	r.deleteCh = make(chan string)

	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		r.createRules(ctx)
	}()
	go func() {
		defer r.wg.Done()
		r.deleteRules(ctx)
	}()

	if err := r.syncContainers(ctx); err != nil {
		r.logger.Error("error syncing containers", zap.Error(err))
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
						r.logger.Error("error parsing label", zap.String("label", enabledLabel), zap.Error(err))
						continue
					}
					if !enabled {
						continue
					}

					if msg.Action == "start" {
						container, err := r.dockerCli.ContainerInspect(ctx, msg.ID)
						if err != nil {
							r.logger.Error("error inspecting container", zap.String("container.id", msg.ID), zap.Error(err))
							continue
						}
						r.createCh <- container
					}
					if msg.Action == "kill" {
						r.deleteCh <- msg.ID
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
					r.logger.Error("error reading docker event stream", zap.Error(err))
				}
				r.logger.Info("recreating docker client")
				r.dockerCli, err = client.NewClientWithOpts(client.FromEnv)
				if err != nil {
					r.logger.Fatal("error creating docker client", zap.Error(err))
				}
				messages, streamErrs = addFilters(ctx, r.dockerCli)
			case <-r.done:
				close(r.createCh)
				close(r.deleteCh)
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
		return fmt.Errorf("error opening database: %w", err)
	}
	// create database schema if a sqlite file doesn't exist
	if dbNotExist {
		if _, err := sqlDB.ExecContext(ctx, dbSchema); err != nil {
			return fmt.Errorf("error creating tables in database: %w", err)
		}
	}
	if _, err := sqlDB.ExecContext(ctx, dbCommands); err != nil {
		return fmt.Errorf("error executing commands in database: %w", err)
	}
	r.db, err = database.NewDB(ctx, sqlDB)
	if err != nil {
		return fmt.Errorf("error preparing database queries: %w", err)
	}

	r.dockerCli, err = client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("error creating docker client: %w", err)
	}

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
		r.logger.Error("error closing docker client", zap.Error(err))
	}
	if err := r.db.Close(); err != nil {
		r.logger.Error("error closing database: %w", zap.Error(err))
	}
}
