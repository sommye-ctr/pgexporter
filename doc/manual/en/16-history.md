\newpage

# History

The history module adds **optional historical storage** so that metric
snapshots are persisted directly by pgexporter. Once enabled, pgexporter
periodically forks a *history worker* that takes a snapshot of all configured
metrics and writes them to a storage backend. A separate *retention worker*
periodically prunes records older than a configured threshold.

The history data is exposed through a JSON HTTP API served on a dedicated
port.

## Configuration

In order to enable history, add the following to `pgexporter.conf`

```ini
[pgexporter]

history          = 5005
history_interval = 60s
history_retention = 30d
history_backend  = sqlite
history_path     = /var/lib/pgexporter/history.db
```

The `history` setting is the port on which the history JSON API will be
served, following the same fork-per-request model as the metrics, console
and bridge endpoints.

If `history` is unset (or `-1`), the history module is disabled and
pgexporter behaves exactly as before.

## Backends

The storage backend is selected with `history_backend`. The currently
supported backends are:

| Backend | Value    | Description |
|---------|----------|-------------|
| SQLite  | `sqlite` | Default. Local file-based storage. |


## Access

The history component acts as a JSON HTTP endpoint. You can access it with

```sh
curl http://localhost:5005/metrics?name=pg_stat_database_xact_commit&from=-1h
```

The endpoint accepts a metric name and a time window and returns the
matching records as JSON.

## Console integration

When `history` is set, the web console queries the history backend for
recent data instead of performing a live scrape. When `history` is not set,
the console behaves exactly as it does today.
