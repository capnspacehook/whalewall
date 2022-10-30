package main

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/capnspacehook/whalewall/database"
)

//go:generate sqlc generate

func (r *ruleManager) addContainer(ctx context.Context, logger *zap.Logger, id, name, service string, addrs map[string][]byte, estContainers map[string]struct{}) error {
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

	// add names the container may have been referred to in user rules
	// so when creating rules that specify this container it can be found
	aliases := []string{"/" + name}
	if service != "" && service != name {
		aliases = append(aliases, service)
		aliases = append(aliases, "/"+service)
	}
	for _, alias := range aliases {
		err := tx.AddContainerAlias(ctx, database.AddContainerAliasParams{
			ContainerID:    id,
			ContainerAlias: alias,
		})
		if err != nil {
			return fmt.Errorf("error adding container alias to database: %w", err)
		}
	}

	// keep track if rules were put into other container's chains so
	// they can be cleaned up when this container is stopped
	for estContainer := range estContainers {
		err := tx.AddEstContainer(ctx, database.AddEstContainerParams{
			SrcContainerID: id,
			DstContainerID: estContainer,
		})
		if err != nil {
			return fmt.Errorf("error adding established container to database: %w", err)
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
		return fmt.Errorf("error deleting container addrs: %w", err)
	}
	if err := tx.DeleteContainerAliases(ctx, id); err != nil {
		return fmt.Errorf("error deleting container aliases: %w", err)
	}
	if err := tx.DeleteEstContainers(ctx, id); err != nil {
		return fmt.Errorf("error deleting established container: %w", err)
	}
	if err := tx.DeleteContainer(ctx, id); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
