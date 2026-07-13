VERSION            ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
COMMIT             := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
# Reproducible build date: honor SOURCE_DATE_EPOCH when set, else derive from the
# HEAD commit time (not wall-clock), so the same commit always builds byte-for-byte
# identical binaries. UTC, RFC3339.
SOURCE_DATE_EPOCH  ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)
DATE               := $(shell date -u -r $(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d @$(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")
GO_VERSION         := $(shell cat .go-version 2>/dev/null || go env GOVERSION | sed 's/go//')
# Tool versions + thresholds read from .settings.yaml (single source of truth,
# shared with CI). Fallbacks keep the Makefile usable without yq installed.
GOLANGCI_VERSION   ?= $(shell yq -r '.linting.golangci_lint' .settings.yaml 2>/dev/null || echo "v2.12.1")
GORELEASER_VERSION ?= $(shell yq -r '.build_tools.goreleaser' .settings.yaml 2>/dev/null || echo "v2.17.0")
SYFT_VERSION       ?= $(shell yq -r '.security_tools.syft' .settings.yaml 2>/dev/null || echo "v1.46.0")
LINT_TIMEOUT       ?= $(shell yq -r '.quality.lint_timeout' .settings.yaml 2>/dev/null || echo "5m")
TEST_TIMEOUT       ?= $(shell yq -r '.quality.test_timeout' .settings.yaml 2>/dev/null || echo "10m")
BUILD_TIMEOUT      ?= $(shell yq -r '.quality.build_timeout' .settings.yaml 2>/dev/null || echo "10m")
COVERAGE_THRESHOLD ?= $(shell yq -r '.quality.coverage_threshold' .settings.yaml 2>/dev/null || echo "35")

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
BIN     := devradarctl

all: help

# =============================================================================
# Info
# =============================================================================

.PHONY: info
info: ## Prints current project info + tool versions
	@echo "version:    $(VERSION)"
	@echo "commit:     $(COMMIT)"
	@echo "date:       $(DATE)"
	@echo "go:         $(GO_VERSION)"
	@echo "golangci:   $(GOLANGCI_VERSION)"
	@echo "goreleaser: $(GORELEASER_VERSION)"
	@echo "syft:       $(SYFT_VERSION)"

# =============================================================================
# Code formatting & dependencies
# =============================================================================

.PHONY: tidy
tidy: ## Formats code and tidies deps
	go fmt ./...
	go mod tidy

.PHONY: fmt-check
fmt-check: ## Verifies code is formatted (CI-friendly, no modifications)
	@test -z "$$(gofmt -l .)" || { echo "Code is not formatted; run 'make tidy':"; gofmt -l .; exit 1; }
	@echo "Formatting check passed"

.PHONY: upgrade
upgrade: ## Upgrades all dependencies to latest and tidies
	go get -u ./...
	go mod tidy

# =============================================================================
# Quality
# =============================================================================

.PHONY: lint
lint: ## Lints Go code (go vet + golangci-lint)
	go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "ERROR: golangci-lint not installed (CI pins $(GOLANGCI_VERSION)); install: https://golangci-lint.run"; exit 1; }
	golangci-lint run --timeout=$(LINT_TIMEOUT)

.PHONY: test
test: ## Runs unit tests with race detector + coverage profile
	go test -count=1 -race -timeout=$(TEST_TIMEOUT) -covermode=atomic -coverprofile=cover.out ./...
	@echo ""; go tool cover -func=cover.out | grep total

.PHONY: test-coverage
test-coverage: test ## Runs tests and enforces the coverage threshold
	@coverage=$$(go tool cover -func=cover.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	echo "Coverage: $$coverage% (threshold: $(COVERAGE_THRESHOLD)%)"; \
	awk "BEGIN { exit !($$coverage >= $(COVERAGE_THRESHOLD)) }" || { \
		echo "ERROR: coverage $$coverage% below threshold $(COVERAGE_THRESHOLD)%"; exit 1; }; \
	echo "Coverage check passed"

.PHONY: vulncheck
vulncheck: ## Scans for known vulnerabilities (govulncheck)
	@command -v govulncheck >/dev/null 2>&1 || { \
		echo "ERROR: govulncheck not installed; run: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	govulncheck ./...

.PHONY: qualify
qualify: fmt-check test-coverage lint ## Full local quality gate (fmt + test + coverage + lint)
	@echo "Qualification complete"

# =============================================================================
# Build & release
# =============================================================================

.PHONY: build
build: ## Builds the CLI to ./bin/devradarctl
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BIN) .

.PHONY: install
install: ## Installs the CLI to GOBIN
	go install -trimpath -ldflags "$(LDFLAGS)" .

.PHONY: snapshot
snapshot: ## Builds a local snapshot release with goreleaser (no publish)
	@command -v goreleaser >/dev/null 2>&1 || { \
		echo "ERROR: goreleaser not installed (CI pins $(GORELEASER_VERSION)); install: https://goreleaser.com"; exit 1; }
	goreleaser release --snapshot --clean --skip=sbom --timeout $(BUILD_TIMEOUT)

.PHONY: release
release: ## Runs a full release (goreleaser); intended for CI on a tag
	@command -v goreleaser >/dev/null 2>&1 || { \
		echo "ERROR: goreleaser not installed (CI pins $(GORELEASER_VERSION)); install: https://goreleaser.com"; exit 1; }
	goreleaser release --clean --timeout $(BUILD_TIMEOUT)

.PHONY: bump-major
bump-major: ## Tags + pushes the next major version (v1.2.3 -> v2.0.0), triggering release
	tools/bump major

.PHONY: bump-minor
bump-minor: ## Tags + pushes the next minor version (v1.2.3 -> v1.3.0), triggering release
	tools/bump minor

.PHONY: bump-patch
bump-patch: ## Tags + pushes the next patch version (v1.2.3 -> v1.2.4), triggering release
	tools/bump patch

# =============================================================================
# Cleanup
# =============================================================================

.PHONY: clean
clean: ## Removes build artifacts
	rm -rf bin dist cover.out
	go clean ./...

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help: ## Prints this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'
