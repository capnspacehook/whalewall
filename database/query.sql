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
