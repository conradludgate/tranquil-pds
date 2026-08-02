# OpenTelemetry tracing

The server can export HTTP request spans over OTLP/HTTP when the `otel` Cargo
feature is enabled. The exporter is opt-in at runtime: without an OTLP
endpoint, Tranquil keeps its normal stdout logging and does not make telemetry
requests.

The SQLite Docker build includes the `otel` feature. The following environment
variables are enough to send spans to a local Jaeger instance or an
OpenTelemetry Collector:

```text
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_SERVICE_NAME=tranquil-pds
OTEL_SERVICE_VERSION=0.6.6
```

The endpoint is the OTLP base URL; the exporter appends `/v1/traces`.

## Local Jaeger test

Start Jaeger with its OTLP/HTTP receiver enabled:

```sh
docker run --rm --name tranquil-jaeger \
  -p 16686:16686 \
  -p 4318:4318 \
  -e COLLECTOR_OTLP_ENABLED=true \
  jaegertracing/all-in-one:latest
```

Run the server with a configuration that passes validation and set:

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
OTEL_SERVICE_NAME=tranquil-pds \
cargo run -p tranquil-server --no-default-features --features sqlite,s3,otel
```

Send a request to the server, then open <http://localhost:16686> and select
`tranquil-pds` from the service list.

## Traceway

For Traceway, prefer sending from Tranquil to an in-cluster OpenTelemetry
Collector. The collector can add the Traceway bearer token and forward OTLP
traces, while the PDS only needs an unauthenticated cluster-local endpoint.
This keeps the Traceway token out of the PDS process environment.
