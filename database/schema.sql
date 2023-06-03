CREATE TABLE containers (
  id   TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
) STRICT;

CREATE TABLE addrs (
  addr         BLOB PRIMARY KEY,
  container_id TEXT NOT NULL,

  FOREIGN KEY(container_id) REFERENCES containers(id)
) STRICT;

CREATE TABLE container_aliases (
  container_id    TEXT NOT NULL,
  container_alias TEXT NOT NULL,

  PRIMARY KEY(container_id, container_alias),
  FOREIGN KEY(container_id) REFERENCES containers(id)
) STRICT;

CREATE TABLE est_containers (
  src_container_id TEXT NOT NULL,
  dst_container_id TEXT NOT NULL,

  PRIMARY KEY(src_container_id, dst_container_id),
  FOREIGN KEY(src_container_id) REFERENCES containers(id),
  FOREIGN KEY(dst_container_id) REFERENCES containers(id)
) STRICT;

CREATE TABLE waiting_container_rules (
  src_container_id   TEXT    NOT NULL,
  dst_container_name TEXT    NOT NULL,
  rule               BLOB    NOT NULL,

  PRIMARY KEY(src_container_id, dst_container_name, rule),
  FOREIGN KEY (src_container_id) REFERENCES containers(id)
) STRICT;
