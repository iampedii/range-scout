APP := range-scout
DIST_DIR := dist
HOST_OS := $(shell go env GOOS)
HOST_ARCH := $(shell go env GOARCH)
TARGET_OS ?= $(HOST_OS)
TARGET_ARCH ?= $(HOST_ARCH)
TARGET_EXT := $(if $(filter windows,$(TARGET_OS)),.exe,)
BUILD_OSES ?= darwin linux windows
BUILD_ARCHES ?= amd64 arm64
RELEASE_VERSION := $(shell git describe --tags --exact-match --match 'v*' 2>/dev/null)
WORKTREE_STATUS := $(shell git status --porcelain 2>/dev/null)
DEV_ARTIFACT := $(DIST_DIR)/$(APP)-$(TARGET_OS)-$(TARGET_ARCH)$(TARGET_EXT)
RELEASE_ARTIFACT := $(DIST_DIR)/$(APP)-$(RELEASE_VERSION)-$(TARGET_OS)-$(TARGET_ARCH)$(TARGET_EXT)

.PHONY: release-version build build-dist build-all build-windows release release-all release-windows release-check run test clean

release-version:
	@echo $(RELEASE_VERSION)

build:
	go build -o $(APP) .

build-dist:
	@mkdir -p $(DIST_DIR)
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) go build -o $(DEV_ARTIFACT) .

build-all:
	@mkdir -p $(DIST_DIR)
	@set -e; \
	for os in $(BUILD_OSES); do \
		for arch in $(BUILD_ARCHES); do \
			ext=""; \
			if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
			out="$(DIST_DIR)/$(APP)-$$os-$$arch$$ext"; \
			echo "building $$out"; \
			GOOS=$$os GOARCH=$$arch go build -o "$$out" .; \
		done; \
	done

build-windows:
	@$(MAKE) build-dist TARGET_OS=windows TARGET_ARCH=amd64

release-check:
	@test -n "$(RELEASE_VERSION)" || (echo "release builds require HEAD to be tagged (for example v0.1.6 or v0.1.6-rc3)"; exit 1)
	@test -z "$(WORKTREE_STATUS)" || (echo "release builds require a clean git worktree"; exit 1)

release: release-check
	@mkdir -p $(DIST_DIR)
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) go build -trimpath -o $(RELEASE_ARTIFACT) .

release-all: release-check
	@mkdir -p $(DIST_DIR)
	@set -e; \
	for os in $(BUILD_OSES); do \
		for arch in $(BUILD_ARCHES); do \
			ext=""; \
			if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
			out="$(DIST_DIR)/$(APP)-$(RELEASE_VERSION)-$$os-$$arch$$ext"; \
			echo "building $$out"; \
			GOOS=$$os GOARCH=$$arch go build -trimpath -o "$$out" .; \
		done; \
	done

release-windows:
	@$(MAKE) release TARGET_OS=windows TARGET_ARCH=amd64

run:
	go run .

test:
	go test ./...

clean:
	rm -f $(APP)
	rm -rf $(DIST_DIR)
