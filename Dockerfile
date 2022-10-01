FROM golang:1.19-alpine AS builder

COPY . /build
WORKDIR /build

ARG CGO_ENABLED=0
RUN go build -ldflags "-s -w" -trimpath -o whalewall

# apparently giving capabilities to containers doesn't work when the
# container isn't running as root inside the container, see
# https://github.com/moby/moby/issues/8460
FROM scratch
COPY --from=builder /build/whalewall /whalewall

ENTRYPOINT [ "/whalewall" ]
CMD [ "-d", "/data" ]
