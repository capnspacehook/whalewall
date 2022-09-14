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

-- name: AddEstContainer :exec
INSERT INTO
	est_containers(src_container_id, dst_container_id)
VALUES
	(
		?,
		?
	);

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

-- name: DeleteEstContainers :exec
DELETE FROM
	est_containers
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
