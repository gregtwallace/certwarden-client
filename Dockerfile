# example build:
# docker build . --build-arg=VERSION=v0.1.0 -t certwarden-client:v0.1.0

# example run
# NOTE: If you don't want or need auto container restart, you can skip mounting docker.sock
# docker run -d --name certwarden-client -e TZ=Europe/Stockholm -v /var/run/docker.sock:/var/run/docker.sock -p 5055:5055 -e [config vars here] ghcr.io/gregtwallace/certwarden-client:latest

# Versions - keep in sync with build_releases.yml
ARG ALPINE_VERSION=3.21
ARG GO_VERSION=1.23.5
# https://hub.docker.com/_/alpine
# https://hub.docker.com/_/golang

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

ARG VERSION

WORKDIR /

RUN apk add git && \
    git clone --depth 1 --branch "${VERSION}" https://github.com/gregtwallace/certwarden-client.git /src && \
    cd /src && \
    go build -o ./certwarden-client ./pkg/main

FROM alpine:${ALPINE_VERSION}

WORKDIR /app

# timezone support
RUN apk add --no-cache tzdata

# copy app
COPY --from=build /src/certwarden-client .
COPY ./README.md .
COPY ./CHANGELOG.md .
COPY ./LICENSE.md .

# https server
EXPOSE 5055/tcp

CMD /app/certwarden-client
