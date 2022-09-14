package main

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/capnspacehook/whalewall/database"
)

func (r *ruleManager) addContainer(ctx context.Context, logger *zap.Logger, id, name string, addrs map[string][]byte) error {
	tx, err := r.db.Begin(ctx, logger)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	err = tx.AddContainer(ctx, database.AddContainerParams{
		ID:   id,
		Name: name,
	})
	if err != nil {
		return fmt.Errorf("error adding container to database: %w", err)
	}

	for _, addr := range addrs {
		err := tx.AddContainerAddr(ctx, database.AddContainerAddrParams{
			Addr:        addr,
			ContainerID: id,
		})
		if err != nil {
			return fmt.Errorf("error adding container addr to database: %w", err)
		}
	}

	return tx.Commit(ctx)
}

func (r *ruleManager) deleteContainer(ctx context.Context, logger *zap.Logger, id string) error {
	tx, err := r.db.Begin(ctx, logger)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := tx.DeleteContainerAddrs(ctx, id); err != nil {
		return fmt.Errorf("error deleting container addrs : %w", err)
	}
	if err := tx.DeleteContainer(ctx, id); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
