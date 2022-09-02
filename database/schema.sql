CREATE TABLE containers (
  id   TEXT PRIMARY KEY,
  name TEXT NOT NULL
);

CREATE TABLE addrs (
  addr         BLOB PRIMARY KEY,
  container_id TEXT NOT NULL,
  FOREIGN KEY(container_id) REFERENCES containers(id)
);
