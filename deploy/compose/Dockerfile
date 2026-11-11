# Multi-stage, offline-capable build: `cargo vendor` output and the pnpm store are
# baked into the build context so no network is needed inside the container.
FROM rust:1.80-bookworm AS build
WORKDIR /src
COPY . .
RUN mkdir -p .cargo && printf '[source.crates-io]\nreplace-with = "vendored"\n[source.vendored]\ndirectory = "vendor"\n' > .cargo/config.toml
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
RUN cargo build --release --offline -p hv-ingest -p hv-api -p hv-analytics -p hv-ca -p hv-feeds -p hv-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd -r -u 10001 hostvigil
COPY --from=build /src/target/release/hv-* /usr/local/bin/
RUN mkdir -p /var/lib/hostvigil && chown hostvigil /var/lib/hostvigil
USER hostvigil
ENTRYPOINT ["/bin/sh", "-c", "exec /usr/local/bin/$0 \"$@\""]
