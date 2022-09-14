CREATE TABLE containers (
  id   TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE addrs (
  addr         BLOB PRIMARY KEY,
  container_id TEXT NOT NULL,

  FOREIGN KEY(container_id) REFERENCES containers(id)
);

CREATE TABLE est_containers (
  src_container_id TEXT NOT NULL,
  dst_container_id TEXT NOT NULL,

  PRIMARY KEY(src_container_id, dst_container_id),
  FOREIGN KEY(src_container_id) REFERENCES containers(id),
  FOREIGN KEY(dst_container_id) REFERENCES containers(id)
);
