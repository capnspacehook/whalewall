-- name: GetContainers :many
SELECT 
	id,
	name
FROM
	containers;

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

-- name: GetContainerName :one
SELECT
	name
FROM
	containers
WHERE
	id = ?;

-- name: GetContainerAddrs :many
SELECT 
	addr
FROM
	addrs
WHERE
	container_id = ?;

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
