// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.17.2
// source: query.sql

package database

import (
	"context"
)

const activateWaitingContainerRules = `-- name: ActivateWaitingContainerRules :exec
UPDATE
	waiting_container_rules
SET
	active = TRUE
WHERE
	dst_container_name = ?
`

func (q *Queries) ActivateWaitingContainerRules(ctx context.Context, dstContainerName string) error {
	_, err := q.exec(ctx, q.activateWaitingContainerRulesStmt, activateWaitingContainerRules, dstContainerName)
	return err
}

const addContainer = `-- name: AddContainer :exec
INSERT INTO
	containers(id, name)
VALUES
	(
		?,
		?
	)
`

type AddContainerParams struct {
	ID   string
	Name string
}

func (q *Queries) AddContainer(ctx context.Context, arg AddContainerParams) error {
	_, err := q.exec(ctx, q.addContainerStmt, addContainer, arg.ID, arg.Name)
	return err
}

const addContainerAddr = `-- name: AddContainerAddr :exec
INSERT INTO
	addrs(addr, container_id)
VALUES
	(
		?,
		?
	)
`

type AddContainerAddrParams struct {
	Addr        []byte
	ContainerID string
}

func (q *Queries) AddContainerAddr(ctx context.Context, arg AddContainerAddrParams) error {
	_, err := q.exec(ctx, q.addContainerAddrStmt, addContainerAddr, arg.Addr, arg.ContainerID)
	return err
}

const addContainerAlias = `-- name: AddContainerAlias :exec
INSERT INTO
	container_aliases(container_id, container_alias)
VALUES
	(
		?,
		?
	)
`

type AddContainerAliasParams struct {
	ContainerID    string
	ContainerAlias string
}

func (q *Queries) AddContainerAlias(ctx context.Context, arg AddContainerAliasParams) error {
	_, err := q.exec(ctx, q.addContainerAliasStmt, addContainerAlias, arg.ContainerID, arg.ContainerAlias)
	return err
}

const addEstContainer = `-- name: AddEstContainer :exec
INSERT INTO
	est_containers(src_container_id, dst_container_id)
VALUES
	(
		?,
		?
	)
`

type AddEstContainerParams struct {
	SrcContainerID string
	DstContainerID string
}

func (q *Queries) AddEstContainer(ctx context.Context, arg AddEstContainerParams) error {
	_, err := q.exec(ctx, q.addEstContainerStmt, addEstContainer, arg.SrcContainerID, arg.DstContainerID)
	return err
}

const addWaitingContainerRule = `-- name: AddWaitingContainerRule :exec
INSERT INTO
	waiting_container_rules
	(
		src_container_id,
		dst_container_name,
		rule,
		active
	)
VALUES
	(
		?,
		?,
		?,
		TRUE
	)
ON CONFLICT(src_container_id, dst_container_name, rule) DO NOTHING
`

type AddWaitingContainerRuleParams struct {
	SrcContainerID   string
	DstContainerName string
	Rule             []byte
}

func (q *Queries) AddWaitingContainerRule(ctx context.Context, arg AddWaitingContainerRuleParams) error {
	_, err := q.exec(ctx, q.addWaitingContainerRuleStmt, addWaitingContainerRule, arg.SrcContainerID, arg.DstContainerName, arg.Rule)
	return err
}

const containerExists = `-- name: ContainerExists :one
SELECT
	EXISTS (
		SELECT
			1
		FROM
			containers
		WHERE
			id = ?
	)
`

func (q *Queries) ContainerExists(ctx context.Context, id string) (interface{}, error) {
	row := q.queryRow(ctx, q.containerExistsStmt, containerExists, id)
	var column_1 interface{}
	err := row.Scan(&column_1)
	return column_1, err
}

const deactivateWaitingContainerRules = `-- name: DeactivateWaitingContainerRules :exec
UPDATE
	waiting_container_rules
SET
	active = FALSE
WHERE
	dst_container_name = ?
`

func (q *Queries) DeactivateWaitingContainerRules(ctx context.Context, dstContainerName string) error {
	_, err := q.exec(ctx, q.deactivateWaitingContainerRulesStmt, deactivateWaitingContainerRules, dstContainerName)
	return err
}

const deleteContainer = `-- name: DeleteContainer :exec
DELETE FROM
	containers
WHERE
	id = ?
`

func (q *Queries) DeleteContainer(ctx context.Context, id string) error {
	_, err := q.exec(ctx, q.deleteContainerStmt, deleteContainer, id)
	return err
}

const deleteContainerAddrs = `-- name: DeleteContainerAddrs :exec
DELETE FROM
	addrs
WHERE
	container_id = ?
`

func (q *Queries) DeleteContainerAddrs(ctx context.Context, containerID string) error {
	_, err := q.exec(ctx, q.deleteContainerAddrsStmt, deleteContainerAddrs, containerID)
	return err
}

const deleteContainerAliases = `-- name: DeleteContainerAliases :exec
DELETE FROM
	container_aliases
WHERE
	container_id = ?
`

func (q *Queries) DeleteContainerAliases(ctx context.Context, containerID string) error {
	_, err := q.exec(ctx, q.deleteContainerAliasesStmt, deleteContainerAliases, containerID)
	return err
}

const deleteEstContainers = `-- name: DeleteEstContainers :exec
DELETE FROM
	est_containers
WHERE
	src_container_id = ? OR
	dst_container_id = ?
`

type DeleteEstContainersParams struct {
	SrcContainerID string
	DstContainerID string
}

func (q *Queries) DeleteEstContainers(ctx context.Context, arg DeleteEstContainersParams) error {
	_, err := q.exec(ctx, q.deleteEstContainersStmt, deleteEstContainers, arg.SrcContainerID, arg.DstContainerID)
	return err
}

const deleteWaitingContainerRules = `-- name: DeleteWaitingContainerRules :exec
DELETE FROM
	waiting_container_rules
WHERE
	src_container_id = ?
`

func (q *Queries) DeleteWaitingContainerRules(ctx context.Context, srcContainerID string) error {
	_, err := q.exec(ctx, q.deleteWaitingContainerRulesStmt, deleteWaitingContainerRules, srcContainerID)
	return err
}

const getContainerAddrs = `-- name: GetContainerAddrs :many
SELECT 
	addr
FROM
	addrs
WHERE
	container_id = ?
`

func (q *Queries) GetContainerAddrs(ctx context.Context, containerID string) ([][]byte, error) {
	rows, err := q.query(ctx, q.getContainerAddrsStmt, getContainerAddrs, containerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items [][]byte
	for rows.Next() {
		var addr []byte
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		items = append(items, addr)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getContainerID = `-- name: GetContainerID :one
SELECT
	id
FROM
	containers
WHERE
	name = ?
`

func (q *Queries) GetContainerID(ctx context.Context, name string) (string, error) {
	row := q.queryRow(ctx, q.getContainerIDStmt, getContainerID, name)
	var id string
	err := row.Scan(&id)
	return id, err
}

const getContainerIDAndNameFromAlias = `-- name: GetContainerIDAndNameFromAlias :one
SELECT
	c.id,
	c.name
FROM
	containers c
JOIN
	container_aliases a
ON
	a.container_id = c.id
WHERE
	a.container_alias = ?
`

func (q *Queries) GetContainerIDAndNameFromAlias(ctx context.Context, containerAlias string) (Container, error) {
	row := q.queryRow(ctx, q.getContainerIDAndNameFromAliasStmt, getContainerIDAndNameFromAlias, containerAlias)
	var i Container
	err := row.Scan(&i.ID, &i.Name)
	return i, err
}

const getContainerName = `-- name: GetContainerName :one
SELECT
	name
FROM
	containers
WHERE
	id = ?
`

func (q *Queries) GetContainerName(ctx context.Context, id string) (string, error) {
	row := q.queryRow(ctx, q.getContainerNameStmt, getContainerName, id)
	var name string
	err := row.Scan(&name)
	return name, err
}

const getContainers = `-- name: GetContainers :many
SELECT 
	id,
	name
FROM
	containers
`

func (q *Queries) GetContainers(ctx context.Context) ([]Container, error) {
	rows, err := q.query(ctx, q.getContainersStmt, getContainers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Container
	for rows.Next() {
		var i Container
		if err := rows.Scan(&i.ID, &i.Name); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEstContainers = `-- name: GetEstContainers :many
SELECT
	e.dst_container_id,
	c.name
FROM
	est_containers e
JOIN
	containers c
ON
	c.id = e.dst_container_id
WHERE
	e.src_container_id = ?
`

type GetEstContainersRow struct {
	DstContainerID string
	Name           string
}

func (q *Queries) GetEstContainers(ctx context.Context, srcContainerID string) ([]GetEstContainersRow, error) {
	rows, err := q.query(ctx, q.getEstContainersStmt, getEstContainers, srcContainerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetEstContainersRow
	for rows.Next() {
		var i GetEstContainersRow
		if err := rows.Scan(&i.DstContainerID, &i.Name); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getWaitingContainerRules = `-- name: GetWaitingContainerRules :many
SELECT
	w.src_container_id,
	c.name,
	w.rule
FROM
	waiting_container_rules w
JOIN
	containers c
ON
	c.id = w.src_container_id
WHERE
	w.dst_container_name = ? AND
	w.active = TRUE
`

type GetWaitingContainerRulesRow struct {
	SrcContainerID string
	Name           string
	Rule           []byte
}

func (q *Queries) GetWaitingContainerRules(ctx context.Context, dstContainerName string) ([]GetWaitingContainerRulesRow, error) {
	rows, err := q.query(ctx, q.getWaitingContainerRulesStmt, getWaitingContainerRules, dstContainerName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetWaitingContainerRulesRow
	for rows.Next() {
		var i GetWaitingContainerRulesRow
		if err := rows.Scan(&i.SrcContainerID, &i.Name, &i.Rule); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
