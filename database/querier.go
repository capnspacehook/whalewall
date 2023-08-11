// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.20.0

package database

import (
	"context"
)

type Querier interface {
	AddContainer(ctx context.Context, iD string, name string) error
	AddContainerAddr(ctx context.Context, addr []byte, containerID string) error
	AddContainerAlias(ctx context.Context, containerID string, containerAlias string) error
	AddEstContainer(ctx context.Context, srcContainerID string, dstContainerID string) error
	AddWaitingContainerRule(ctx context.Context, arg AddWaitingContainerRuleParams) error
	ContainerExists(ctx context.Context, id string) (int64, error)
	DeleteContainer(ctx context.Context, id string) error
	DeleteContainerAddrs(ctx context.Context, containerID string) error
	DeleteContainerAliases(ctx context.Context, containerID string) error
	DeleteEstContainers(ctx context.Context, srcContainerID string, dstContainerID string) error
	DeleteWaitingContainerRules(ctx context.Context, srcContainerID string) error
	GetContainerAddrs(ctx context.Context, containerID string) ([][]byte, error)
	GetContainerID(ctx context.Context, name string) (string, error)
	GetContainerIDAndNameFromAlias(ctx context.Context, containerAlias string) (Container, error)
	GetContainerName(ctx context.Context, id string) (string, error)
	GetContainers(ctx context.Context) ([]Container, error)
	GetEstContainers(ctx context.Context, srcContainerID string) ([]GetEstContainersRow, error)
	GetWaitingContainerRules(ctx context.Context, dstContainerName string) ([]GetWaitingContainerRulesRow, error)
}

var _ Querier = (*Queries)(nil)
