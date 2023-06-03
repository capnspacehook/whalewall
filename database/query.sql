-- name: AddContainer :exec
INSERT INTO
	containers(id, name)
VALUES
	(
		?,
		?
	);

-- name: AddContainerAddr :exec
INSERT INTO
	addrs(addr, container_id)
VALUES
	(
		?,
		?
	);

-- name: AddContainerAlias :exec
INSERT INTO
	container_aliases(container_id, container_alias)
VALUES
	(
		?,
		?
	);

-- name: AddEstContainer :exec
INSERT INTO
	est_containers(src_container_id, dst_container_id)
VALUES
	(
		?,
		?
	);

-- name: AddWaitingContainerRule :exec
INSERT INTO
	waiting_container_rules
	(
		src_container_id,
		dst_container_name,
		rule
	)
VALUES
	(
		?,
		?,
		?
	)
ON CONFLICT(src_container_id, dst_container_name, rule) DO NOTHING;

-- name: ContainerExists :one
SELECT
	EXISTS (
		SELECT
			1
		FROM
			containers
		WHERE
			id = ?
	);

-- name: DeleteContainer :exec
DELETE FROM
	containers
WHERE
	id = ?;

-- name: DeleteContainerAddrs :exec
DELETE FROM
	addrs
WHERE
	container_id = ?;

-- name: DeleteContainerAliases :exec
DELETE FROM
	container_aliases
WHERE
	container_id = ?;

-- name: DeleteEstContainers :exec
DELETE FROM
	est_containers
WHERE
	src_container_id = ? OR
	dst_container_id = ?;

-- name: DeleteWaitingContainerRules :exec
DELETE FROM
	waiting_container_rules
WHERE
	src_container_id = ?;

-- name: GetContainerAddrs :many
SELECT 
	addr
FROM
	addrs
WHERE
	container_id = ?;

-- name: GetContainerID :one
SELECT
	id
FROM
	containers
WHERE
	name = ?;

-- name: GetContainerName :one
SELECT
	name
FROM
	containers
WHERE
	id = ?;

-- name: GetContainerIDAndNameFromAlias :one
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
	a.container_alias = ?;

-- name: GetContainers :many
SELECT 
	id,
	name
FROM
	containers;

-- name: GetEstContainers :many
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
	e.src_container_id = ?;

-- name: GetWaitingContainerRules :many
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
	w.dst_container_name = ?;
