package whalewall

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
	"github.com/docker/docker/client"
	"github.com/google/nftables"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"github.com/capnspacehook/whalewall/database"
)

const (
	dbCommands = `
PRAGMA foreign_keys = true;
PRAGMA busy_timeout = 1000;
PRAGMA journal_mode = WAL;
`
	dummyID   = "dummy_id"
	dummyName = "dummy_name"

	enabledLabel = "whalewall.enabled"
	rulesLabel   = "whalewall.rules"
)

//go:embed database/schema.sql
var dbSchema string

type RuleManager struct {
	wg       sync.WaitGroup
	stopping chan struct{}
	done     chan struct{}

	logger *zap.Logger

	newDockerClient   dockerClientCreator
	newFirewallClient firewallClientCreator

	createCh chan containerDetails
	deleteCh chan string

	db        *database.DB
	dockerCli dockerClient
}

type dockerClientCreator func() (dockerClient, error)

type firewallClientCreator func() (firewallClient, error)

type containerDetails struct {
	container types.ContainerJSON
	isNew     bool
}

func NewRuleManager(ctx context.Context, logger *zap.Logger, dbFile string, timeout time.Duration) (*RuleManager, error) {
	r := RuleManager{
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
		logger:   logger,
		newDockerClient: func() (dockerClient, error) {
			dc, err := client.NewClientWithOpts(client.FromEnv)
			if err != nil {
				return nil, err
			}
			return &wrappedDockerClient{
				timeout:      timeout,
				dockerClient: dc,
			}, nil
		},
		newFirewallClient: func() (firewallClient, error) {
			return nftables.New()
		},
	}
	err := r.initDB(ctx, dbFile)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func (r *RuleManager) setDockerClientCreator(dc dockerClientCreator) {
	r.newDockerClient = dc
}

func (r *RuleManager) setFirewallClientCreator(fc firewallClientCreator) {
	r.newFirewallClient = fc
}

func (r *RuleManager) Start(ctx context.Context) error {
	if err := r.init(ctx); err != nil {
		return err
	}
	if err := r.createBaseRules(); err != nil {
		return fmt.Errorf("error creating base rules: %w", err)
	}

	if err := r.cleanupRules(ctx); err != nil {
		r.logger.Error("error cleaning up rules", zap.Error(err))
	}

	r.createCh = make(chan containerDetails)
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
						r.createCh <- containerDetails{
							container: container,
							isNew:     true,
						}
					}
					if msg.Action == "die" {
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
				_, err = r.dockerCli.Ping(ctx)
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

func (r *RuleManager) init(ctx context.Context) error {
	dockerCli, err := r.newDockerClient()
	if err != nil {
		return fmt.Errorf("error creating docker client: %w", err)
	}
	r.dockerCli = dockerCli
	_, err = r.dockerCli.Ping(ctx)
	if err != nil {
		return fmt.Errorf("error connecting to docker daemon: %w", err)
	}
	return nil
}

func (r *RuleManager) initDB(ctx context.Context, dbFile string) error {
	// create data directory if it doesn't exist
	dbDir := filepath.Dir(dbFile)
	if _, err := os.Stat(dbDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.logger.Info("creating data directory", zap.String("data.dir", dbDir))
			if err := os.MkdirAll(dbDir, 0o750); err != nil {
				return fmt.Errorf("error creating data directory: %w", err)
			}
		} else {
			return err
		}
	}

	var dbNotExist bool
	if _, err := os.Stat(dbFile); err != nil {
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
		defer tx.Rollback()

		if err = tx.AddContainer(ctx, dummyID, dummyName); err != nil {
			return fmt.Errorf("error adding container to database: %w", err)
		}
		err = tx.DeleteContainer(ctx, dummyID)
		if err != nil {
			return fmt.Errorf("error deleting container in database: %w", err)
		}
		return tx.Commit()
	}

	return nil
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
			Value: "die",
		},
	)
	return client.Events(ctx, types.EventsOptions{Filters: filter})
}

func (r *RuleManager) Done() <-chan struct{} {
	return r.done
}

func (r *RuleManager) Stop() {
	r.stopping <- struct{}{}
	r.wg.Wait()

	if err := r.dockerCli.Close(); err != nil {
		r.logger.Error("error closing docker client", zap.Error(err))
	}
	if err := r.db.Close(); err != nil {
		r.logger.Error("error closing database: %w", zap.Error(err))
	}
}
