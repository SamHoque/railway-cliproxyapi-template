ARG UPSTREAM_IMAGE=eceasy/cli-proxy-api@sha256:6c2c8a7904799bd29a3f7f92a598555d8321b6a5682000b87af4495c5704fa72
FROM golang:1.25.5-bookworm@sha256:d9132cce84391efab786495288756d60e1da215b1f94e87860aeefc3d4c45b6d AS health_proxy_builder
ARG EMBEDDED_VERSION=v7.3.8
WORKDIR /src
COPY health-proxy.go .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.embeddedVersion=${EMBEDDED_VERSION}" \
    -o /out/health-proxy health-proxy.go
COPY config-reconciler.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/config-reconciler config-reconciler.go

FROM scratch AS management_asset
ADD --checksum=sha256:e2643e0875e0024e5ff9ddf4569e4c58611ab0456aeb6fa6065ed3e6c2b721f4 \
    https://github.com/router-for-me/Cli-Proxy-API-Management-Center/releases/download/v1.22.6/management.html \
    /management.html

ARG UPSTREAM_IMAGE=eceasy/cli-proxy-api@sha256:6c2c8a7904799bd29a3f7f92a598555d8321b6a5682000b87af4495c5704fa72
FROM ${UPSTREAM_IMAGE}

COPY --from=health_proxy_builder /out/health-proxy /usr/local/bin/health-proxy
COPY --from=health_proxy_builder /out/config-reconciler /usr/local/bin/config-reconciler
COPY --from=management_asset /management.html /opt/cliproxy/management.html
COPY entrypoint.sh /usr/local/bin/cliproxy-entrypoint
RUN chmod 0755 /usr/local/bin/health-proxy /usr/local/bin/config-reconciler /usr/local/bin/cliproxy-entrypoint \
    && chmod 0644 /opt/cliproxy/management.html \
    && groupadd --gid 10001 cliproxy \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /data/home --shell /usr/sbin/nologin cliproxy

ENV PORT=8080 \
    MANAGEMENT_STATIC_PATH=/opt/cliproxy/management.html
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/cliproxy-entrypoint"]
