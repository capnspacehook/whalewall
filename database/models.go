// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.15.0

package database

import ()

type Addr struct {
	Addr        []byte
	ContainerID string
}

type Container struct {
	ID   string
	Name string
}

type ContainerAlias struct {
	ContainerID    string
	ContainerAlias string
}

type EstContainer struct {
	SrcContainerID string
	DstContainerID string
}
