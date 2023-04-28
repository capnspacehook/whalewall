package whalewall

import (
	"context"
	"fmt"

	"github.com/capnspacehook/whalewall/database"
)

//go:generate sqlc generate

func (r *RuleManager) containerExists(ctx context.Context, db database.Querier, id string) (bool, error) {
	exists, err := db.ContainerExists(ctx, id)
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}

func (r *RuleManager) addContainer(ctx context.Context, tx *database.TX, id, name, service string, addrs map[string][]byte, estContainers map[string]struct{}) error {
	for _, addr := range addrs {
		err := tx.AddContainerAddr(ctx, addr, id)
		if err != nil {
			return fmt.Errorf("error adding container addr to database: %w", err)
		}
	}

	// add names the container may have been referred to in user rules
	// so when creating rules that specify this container it can be found
	aliases := containerAliases(name, service)
	for _, alias := range aliases {
		err := tx.AddContainerAlias(ctx, id, alias)
		if err != nil {
			return fmt.Errorf("error adding container alias to database: %w", err)
		}
	}

	// keep track if rules were put into other container's chains so
	// they can be cleaned up when this container is stopped
	for estContainer := range estContainers {
		err := tx.AddEstContainer(ctx, id, estContainer)
		if err != nil {
			return fmt.Errorf("error adding established container to database: %w", err)
		}
	}

	return tx.Commit()
}

func containerAliases(name, service string) []string {
	aliases := []string{"/" + name}
	if service != "" && service != name {
		aliases = append(aliases, service)
		aliases = append(aliases, "/"+service)
	}
	return aliases
}

func (r *RuleManager) deleteContainer(ctx context.Context, tx *database.TX, id, name string) error {
	if err := tx.DeleteContainerAddrs(ctx, id); err != nil {
		return fmt.Errorf("error deleting container addrs in database: %w", err)
	}
	if err := tx.DeleteContainerAliases(ctx, id); err != nil {
		return fmt.Errorf("error deleting container aliases in database: %w", err)
	}
	if err := tx.DeleteEstContainers(ctx, id, id); err != nil {
		return fmt.Errorf("error deleting established container in database: %w", err)
	}
	// delete waiting container rules that this container created
	if err := tx.DeleteWaitingContainerRules(ctx, id); err != nil {
		return fmt.Errorf("error deleting waiting container rules in database: %w", err)
	}
	// activate waiting container rules concerning this container so
	// that if it restarts those rules can be recreated
	if err := tx.ActivateWaitingContainerRules(ctx, name); err != nil {
		return fmt.Errorf("error updating waiting container rules in database: %w", err)
	}
	if err := tx.DeleteContainer(ctx, id); err != nil {
		return fmt.Errorf("error deleting container in database: %w", err)
	}

	return tx.Commit()
}
