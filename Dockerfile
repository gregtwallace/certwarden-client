# example build:
# docker build . --build-arg=VERSION=v0.1.0 -t legocerthub-client:v0.1.0

# example run
# NOTE: If you don't want or need auto container restart, you can skip mounting docker.sock
# docker run -d --name legocerthub-client -e TZ=Europe/Stockholm -v /var/run/docker.sock:/var/run/docker.sock -p 5055:5055 -e [config vars here] ghcr.io/gregtwallace/legocerthub-client:latest

# Versions - keep in sync with build_releases.yml
ARG ALPINE_VERSION=3.17
ARG GO_VERSION=1.22.0
# https://hub.docker.com/_/alpine
# https://hub.docker.com/_/golang

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

ARG VERSION

WORKDIR /

RUN apk add git && \
    git clone --depth 1 --branch "${VERSION}" https://github.com/gregtwallace/legocerthub-client.git /src && \
    cd /src && \
    go build -o ./lego-client ./pkg/main

FROM alpine:${ALPINE_VERSION}

WORKDIR /app

# timezone support
RUN apk add --no-cache tzdata

# copy app
COPY --from=build /src/lego-client .
COPY ./README.md .
COPY ./CHANGELOG.md .
COPY ./LICENSE.md .

# https server
EXPOSE 5055/tcp

CMD /app/lego-client
