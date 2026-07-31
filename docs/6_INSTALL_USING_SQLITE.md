# Installing Tranquil with SQLite

SQLite is supported for a single-node Tranquil deployment. It uses WAL mode,
foreign keys, and a busy timeout, and is suitable for continuous Litestream
replication.

Set the repository backend and database URL in `config.toml`:

```toml
[database]
url = "sqlite:///var/lib/tranquil-pds/pds.db"

[storage]
repo_backend = "sqlite"
```

Keep the database on persistent local storage and include the database file and
its WAL file in the Litestream replica configuration. Do not run multiple PDS
processes against the same SQLite database. Filesystem or S3 blob storage can
be selected independently.

The container image can be built with the SQLite backend:

```sh
docker build --build-arg BACKEND=sqlite -t tranquil-pds:sqlite .
```

SQLite migrations are applied automatically on startup. Litestream should be
configured to replicate the database while the PDS is running; restore the
database before starting Tranquil on a replacement host.
