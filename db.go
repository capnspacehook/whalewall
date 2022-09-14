package main

import (
	"context"
	"fmt"

	"github.com/capnspacehook/whalewall/database"
)

func (r *ruleManager) addContainer(ctx context.Context, id, name string, addrs map[string][]byte) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	err = tx.AddContainer(ctx, database.AddContainerParams{
		ID:   id,
		Name: name,
	})
	if err != nil {
		return fmt.Errorf("error adding container to database: %v", err)
	}

	for _, addr := range addrs {
		err := tx.AddContainerAddr(ctx, database.AddContainerAddrParams{
			Addr:        addr,
			ContainerID: id,
		})
		if err != nil {
			return fmt.Errorf("error adding container addr to database: %v", err)
		}
	}

	return tx.Commit(ctx)
}

func (r *ruleManager) deleteContainer(ctx context.Context, id string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := tx.DeleteContainerAddrs(ctx, id); err != nil {
		return fmt.Errorf("error deleting container addrs from database: %v", err)
	}
	if err := tx.DeleteContainer(ctx, id); err != nil {
		return fmt.Errorf("error deleting container from database: %v", err)
	}

	return tx.Commit(ctx)
}
