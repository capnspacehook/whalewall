package main

import (
	"context"
	"log"

	"github.com/capnspacehook/whalewall/database"
)

func (r *ruleManager) addContainer(ctx context.Context, id, name string, addrs map[string][]byte) bool {
	tx, ok := r.db.Begin(ctx)
	if !ok {
		return false
	}
	defer tx.Rollback(ctx)

	err := tx.AddContainer(ctx, database.AddContainerParams{
		ID:   id,
		Name: name,
	})
	if err != nil {
		log.Printf("error adding container to database: %v", err)
		return false
	}

	for _, addr := range addrs {
		err := tx.AddContainerAddr(ctx, database.AddContainerAddrParams{
			Addr:        addr,
			ContainerID: id,
		})
		if err != nil {
			log.Printf("error adding container addr to database: %v", err)
			return false
		}
	}

	return tx.Commit(ctx)
}

func (r *ruleManager) deleteContainer(ctx context.Context, id string) bool {
	tx, ok := r.db.Begin(ctx)
	if !ok {
		return false
	}
	defer tx.Rollback(ctx)

	if err := tx.DeleteContainerAddrs(ctx, id); err != nil {
		log.Printf("error deleting container addrs from database: %v", err)
		return false
	}
	if err := tx.DeleteContainer(ctx, id); err != nil {
		log.Printf("error deleting container from database: %v", err)
		return false
	}

	return tx.Commit(ctx)
}
