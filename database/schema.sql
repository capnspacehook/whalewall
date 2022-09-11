CREATE TABLE containers (
  id   TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE addrs (
  addr         BLOB PRIMARY KEY,
  container_id TEXT NOT NULL,
  FOREIGN KEY(container_id) REFERENCES containers(id)
);
