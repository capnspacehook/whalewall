FROM golang:1.20.2-alpine AS builder

COPY . /build
WORKDIR /build/cmd/whalewall

# add git so VCS info will be stamped in binary
# ignore warning that a specific version of git isn't pinned
# hadolint ignore=DL3018
RUN apk add --no-cache git

# build as PIE to take advantage of exploit mitigations
ARG CGO_ENABLED=0
ARG VERSION
RUN go build -buildmode pie -buildvcs=true -ldflags "-s -w -X main.version=${VERSION}" -trimpath -o whalewall

# pie-loader is built and scanned daily, we want the most recent version
# hadolint ignore=DL3007
FROM ghcr.io/capnspacehook/pie-loader:latest
COPY --from=builder /build/cmd/whalewall/whalewall /whalewall

# apparently giving capabilities to containers doesn't work when the
# container isn't running as root inside the container, see
# https://github.com/moby/moby/issues/8460

ENTRYPOINT [ "/whalewall" ]
CMD [ "-d", "/data" ]
