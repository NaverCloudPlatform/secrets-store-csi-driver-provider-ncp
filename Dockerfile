# NCP Secrets Store CSI Driver Provider
# Copyright (c) 2026-present NAVER Cloud Corp.
# Apache-2.0
#
# Multi-platform capable: the builder stage runs natively on the build host and
# cross-compiles for whichever platform buildx targets. Released images are
# linux/amd64; other architectures build the same way via --platform.
#
# Base images are written out rather than built from ARGs: Dependabot skips a
# FROM whose image comes from a build arg, and these two carry the Go standard
# library and the OS packages the image ships. Keep the Alpine versions equal.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine3.23 AS builder
ARG VERSION=dev
# Redeclared without a value on purpose: buildx fills these from --platform, and
# giving them a default here pins that default instead, so every platform got an
# amd64 binary inside a correctly-labelled image.
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY pkg/ pkg/
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/pkg/server.Version=${VERSION}" \
    -o bin/secrets-store-csi-driver-provider-ncp ./cmd

FROM alpine:3.23
ARG VERSION=dev
LABEL org.opencontainers.image.title="secrets-store-csi-driver-provider-ncp" \
      org.opencontainers.image.description="NCP Secret Manager provider for the Secrets Store CSI Driver" \
      org.opencontainers.image.source="https://github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/bin/secrets-store-csi-driver-provider-ncp /usr/local/bin/
ENTRYPOINT ["secrets-store-csi-driver-provider-ncp"]
