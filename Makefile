# NCP Secrets Store CSI Driver Provider
# Copyright (c) 2026-present NAVER Cloud Corp.
# Apache-2.0

BINARY     := secrets-store-csi-driver-provider-ncp
BUILD_DIR  := bin
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -s -w -X 'github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/pkg/server.Version=$(VERSION)'
REGISTRY   ?= nks.kr.ncr.ntruss.com
IMAGE_NAME ?= secrets-store-csi-driver-provider-ncp
IMAGE_TAG  ?= $(VERSION)
FULL_IMAGE ?= $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
PLATFORMS  ?= linux/amd64

.PHONY: build test lint fmt tidy clean docker-build docker-push

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd

test:
	go test ./... -v -race -count=1

lint:
	golangci-lint run ./...

fmt:
	golangci-lint fmt ./...

tidy:
	go mod tidy

clean:
	rm -rf $(BUILD_DIR)

# --load accepts a single platform only. For more than one, use docker-push:
#   make docker-push PLATFORMS=linux/amd64,linux/arm64
docker-build:
	docker buildx build --platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		-t $(FULL_IMAGE) --load .

docker-push:
	docker buildx build --platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		-t $(FULL_IMAGE) --push .
