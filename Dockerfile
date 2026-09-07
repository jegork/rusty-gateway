FROM --platform=$BUILDPLATFORM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /gateway ./cmd/gateway

FROM node:22-bookworm-slim AS node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# runtimes for stdio upstreams: node + npm from the official image, uv from astral
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /uvx /usr/local/bin/

# the gateway passes an explicit env to children; these paths are what
# gateway.toml should reference for UV_CACHE_DIR / npm_config_cache
RUN useradd --create-home --uid 1000 gateway \
    && mkdir -p /data /var/cache/uv /var/cache/npm \
    && chown -R gateway:gateway /data /var/cache/uv /var/cache/npm
COPY --from=build /gateway /usr/local/bin/gateway
USER gateway
WORKDIR /data
ENV HOME=/home/gateway UV_CACHE_DIR=/var/cache/uv npm_config_cache=/var/cache/npm
VOLUME ["/data", "/var/cache/uv", "/var/cache/npm"]
EXPOSE 8080
ENTRYPOINT ["gateway"]
CMD ["-config", "/etc/gateway/gateway.toml"]
