FROM --platform=$BUILDPLATFORM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /gateway ./cmd/gateway

# upstream MCP servers need their own runtimes; layer them on top of this
# image (uv, node, prebuilt binaries) rather than using npx/uvx at start
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /gateway /usr/local/bin/gateway
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["gateway"]
CMD ["-config", "/etc/gateway/gateway.toml"]
