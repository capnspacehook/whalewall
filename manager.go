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
	"path/filepath"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"github.com/capnspacehook/whalewall/database"
)

const (
	dbFilename = "db.sqlite"
	dbCommands = `
PRAGMA busy_timeout = 1000;
PRAGMA journal_mode=WAL;
`
	dummyID   = "dummy_id"
	dummyName = "dummy_name"

	enabledLabel = "whalewall.enabled"
	rulesLabel   = "whalewall.rules"
)

//go:embed database/schema.sql
var dbSchema string

type ruleManager struct {
	wg       sync.WaitGroup
	stopping chan struct{}
	done     chan struct{}

	logger  *zap.Logger
	timeout time.Duration

	newDockerClient   dockerClientCreator
	newFirewallClient firewallClientCreator

	createCh chan types.ContainerJSON
	deleteCh chan string

	db        *database.DB
	dockerCli dockerClient
}

type dockerClientCreator func() (dockerClient, error)

type firewallClientCreator func() (firewallClient, error)

func newRuleManager(ctx context.Context, logger *zap.Logger, dataDir string, timeout time.Duration, dc dockerClientCreator, fc firewallClientCreator) (*ruleManager, error) {
	r := ruleManager{
		stopping:          make(chan struct{}),
		done:              make(chan struct{}),
		logger:            logger,
		timeout:           timeout,
		newDockerClient:   dc,
		newFirewallClient: fc,
	}
	err := r.initDB(ctx, dataDir)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func (r *ruleManager) start(ctx context.Context) error {
	if err := r.init(ctx); err != nil {
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
						container, err := withTimeout(ctx, r.timeout, func(ctx context.Context) (types.ContainerJSON, error) {
							return r.dockerCli.ContainerInspect(ctx, msg.ID)
						})
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
				r.logger.Info("attempting to reconnect to docker daemon")
				_, err = withTimeout(ctx, r.timeout, func(ctx context.Context) (types.Ping, error) {
					return r.dockerCli.Ping(ctx)
				})
				if err != nil {
					r.logger.Error("error connecting to docker daemon", zap.Error(err))
					r.done <- struct{}{}
					continue
				}

				messages, streamErrs = addFilters(ctx, r.dockerCli)
			case <-r.stopping:
				close(r.createCh)
				close(r.deleteCh)
				return
			}
		}
	}()

	return nil
}

func (r *ruleManager) init(ctx context.Context) error {
	dockerCli, err := r.newDockerClient()
	if err != nil {
		return fmt.Errorf("error creating docker client: %w", err)
	}
	r.dockerCli = dockerCli
	_, err = withTimeout(ctx, r.timeout, func(ctx context.Context) (types.Ping, error) {
		return r.dockerCli.Ping(ctx)
	})
	if err != nil {
		return fmt.Errorf("error connecting to docker daemon: %w", err)
	}
	return nil
}

func (r *ruleManager) initDB(ctx context.Context, dataDir string) error {
	// create data directory if it doesn't exist
	dataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	_, err = os.Stat(dataDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.logger.Info("creating data directory", zap.String("data.dir", dataDir))
			if err := os.MkdirAll(dataDir, 0o750); err != nil {
				return fmt.Errorf("error creating data directory: %w", err)
			}
		} else {
			return err
		}
	}
	dbFile := filepath.Join(dataDir, dbFilename)

	var dbNotExist bool
	_, err = os.Stat(dbFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			dbNotExist = true
		} else {
			return err
		}
	}

	sqlDB, err := sql.Open("sqlite", dbFile)
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}
	// create database schema if a SQLite database didn't exist
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
	// SQLite will lazily create WAL files when something is first
	// written to the database, and landlock requires that files exist
	// in order to set rules on them. So we commit a no-op transaction
	// just so SQLite will create the WAL files and make landlock happy.
	if dbNotExist {
		tx, err := r.db.Begin(ctx, r.logger)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)

		err = r.db.AddContainer(ctx, database.AddContainerParams{
			ID:   dummyID,
			Name: dummyName,
		})
		if err != nil {
			return fmt.Errorf("error adding container to database: %w", err)
		}
		err = r.db.DeleteContainer(ctx, dummyID)
		if err != nil {
			return fmt.Errorf("error deleting container in database: %w", err)
		}
		return tx.Commit(ctx)
	}

	return nil
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
// that uses ctx immediately failing.
func withTimeout[T any](ctx context.Context, timeout time.Duration, f func(ctx context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return f(ctx)
}

func addFilters(ctx context.Context, client dockerClient) (<-chan events.Message, <-chan error) {
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

func (r *ruleManager) isDone() <-chan struct{} {
	return r.done
}

func (r *ruleManager) stop() {
	r.stopping <- struct{}{}
	r.wg.Wait()

	if err := r.dockerCli.Close(); err != nil {
		r.logger.Error("error closing docker client", zap.Error(err))
	}
	if err := r.db.Close(); err != nil {
		r.logger.Error("error closing database: %w", zap.Error(err))
	}
}
