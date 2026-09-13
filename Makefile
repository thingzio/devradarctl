VERSION            ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
COMMIT             := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
# Reproducible build date: honor SOURCE_DATE_EPOCH when set, else derive from the
# HEAD commit time (not wall-clock), so the same commit always builds byte-for-byte
# identical binaries. UTC, RFC3339.
SOURCE_DATE_EPOCH  ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)
DATE               := $(shell date -u -r $(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d @$(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")
GO_VERSION         := $(shell cat .go-version 2>/dev/null || go env GOVERSION | sed 's/go//')

# Every pinned version comes from .versions.yaml so that a local `make lint`
# and the CI job run the identical tool. Parsed with sed rather than yq to
# keep `make help` working on a machine with nothing installed yet -- and so
# there is no second copy of each version living in a shell fallback, which is
# exactly the drift .versions.yaml exists to prevent.
VERSIONS            := .versions.yaml
version-of           = $(shell sed -n 's/^[[:space:]]*$(1):[[:space:]]*.\(.*\).[[:space:]]*$$/\1/p' $(VERSIONS) | head -1)

GOLANGCI_VERSION   := $(call version-of,golangci_lint)
GORELEASER_VERSION := $(call version-of,goreleaser)
SYFT_VERSION       := $(call version-of,syft)
GOVULNCHECK_VERSION := $(call version-of,govulncheck)
ACTIONLINT_VERSION := $(call version-of,actionlint)
YAMLLINT_VERSION   := $(call version-of,yamllint)
GITLEAKS_VERSION   := $(call version-of,gitleaks)
LINT_TIMEOUT       := $(call version-of,lint_timeout)
TEST_TIMEOUT       := $(call version-of,test_timeout)
BUILD_TIMEOUT      := $(call version-of,build_timeout)
COVERAGE_THRESHOLD := $(call version-of,coverage_threshold)

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
BIN     := devradarctl

# Pinned tools are installed here rather than expected on PATH, so `make lint`
# locally and the lint job in CI cannot run different versions of the same
# binary. Prepended to PATH so recipes can call them by bare name.
TOOLS_DIR := $(CURDIR)/bin/tools
export PATH := $(TOOLS_DIR):$(PATH)

# Each pinned tool is gated on a version-stamped sentinel rather than on the
# binary itself. Keying the target on bin/tools/govulncheck would mean that once
# the file existed make considered it done forever: bumping the pin in
# .versions.yaml would reinstall nothing locally while CI, starting from an
# empty runner, got the new version. That is precisely the local-vs-CI drift
# this file exists to prevent, and it is invisible -- the gate still passes,
# just with the wrong tool.
#
# These must be defined above the rules that name them: make expands
# prerequisites when it reads the rule, so a stamp defined further down the file
# expands to the empty string and the tool dependency silently disappears.
GOLANGCI_LINT_STAMP := $(TOOLS_DIR)/.golangci-lint-$(GOLANGCI_VERSION)
GOVULNCHECK_STAMP   := $(TOOLS_DIR)/.govulncheck-$(GOVULNCHECK_VERSION)
ACTIONLINT_STAMP    := $(TOOLS_DIR)/.actionlint-$(ACTIONLINT_VERSION)
GITLEAKS_STAMP      := $(TOOLS_DIR)/.gitleaks-$(GITLEAKS_VERSION)
SYFT_STAMP          := $(TOOLS_DIR)/.syft-$(SYFT_VERSION)

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
	@echo "vulncheck:  $(GOVULNCHECK_VERSION)"
	@echo "actionlint: $(ACTIONLINT_VERSION)"
	@echo "yamllint:   $(YAMLLINT_VERSION)"
	@echo "gitleaks:   $(GITLEAKS_VERSION)"

# =============================================================================
# Code formatting & dependencies
# =============================================================================

.PHONY: tidy
tidy: ## Formats code and tidies deps
	go fmt ./...
	go mod tidy
	go mod verify
	$(MAKE) notices

.PHONY: notices
notices: ## Regenerate THIRD_PARTY_NOTICES.md from the build graph
	python3 tools/gen-third-party-notices

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
lint: $(GOLANGCI_LINT_STAMP) ## Lints Go code (go vet + golangci-lint)
	go vet ./...
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
vulncheck: $(GOVULNCHECK_STAMP) ## Scans for known vulnerabilities (govulncheck)
	govulncheck ./...

.PHONY: license
license: ## Applies the Apache-2.0 header to every first-party Go file
	python3 tools/apply-license-headers

.PHONY: license-check
license-check: ## Fails if any first-party Go file is missing its license header
	python3 tools/apply-license-headers --check

.PHONY: lint-yaml
lint-yaml: ## Lints YAML with the pinned yamllint
	@command -v yamllint >/dev/null 2>&1 \
		|| { echo "yamllint not installed: pipx install yamllint==$(YAMLLINT_VERSION)"; exit 1; }
	yamllint --strict .

.PHONY: lint-actions
lint-actions: $(ACTIONLINT_STAMP) ## Lints GitHub Actions workflows
	actionlint

.PHONY: secrets
secrets: $(GITLEAKS_STAMP) ## Scans the working tree and full history for secrets
	gitleaks dir --no-banner --redact .
	gitleaks git --no-banner --redact .

# What CI runs. Keep this the single definition of "green" so a local run and a
# pull-request run cannot disagree.
#
# lint-yaml is deliberately absent: yamllint is a Python tool installed with
# pipx rather than `go install`, so CI runs it as its own step instead of
# making every contributor install it to commit a Go change.
.PHONY: qualify
qualify: fmt-check license-check test-coverage lint lint-actions secrets vulncheck ## Full local quality gate (mirrors CI)
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

# Tagging is the one action that cannot be taken back: a tag names bytes other
# people will verify against. tools/bump refuses a dirty tree, refuses unpushed
# commits, and runs `make qualify` before it tags.
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
# Tools
# =============================================================================

$(TOOLS_DIR):
	mkdir -p $(TOOLS_DIR)

$(GOLANGCI_LINT_STAMP): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	rm -f $(TOOLS_DIR)/.golangci-lint-* && touch $@

$(GOVULNCHECK_STAMP): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	rm -f $(TOOLS_DIR)/.govulncheck-* && touch $@

$(ACTIONLINT_STAMP): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
	rm -f $(TOOLS_DIR)/.actionlint-* && touch $@

$(GITLEAKS_STAMP): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)
	rm -f $(TOOLS_DIR)/.gitleaks-* && touch $@

$(SYFT_STAMP): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/anchore/syft/cmd/syft@$(SYFT_VERSION)
	rm -f $(TOOLS_DIR)/.syft-* && touch $@

.PHONY: tools
tools: $(GOLANGCI_LINT_STAMP) $(GOVULNCHECK_STAMP) $(ACTIONLINT_STAMP) $(GITLEAKS_STAMP) ## Installs the pinned dev tools into bin/tools

# =============================================================================
# Cleanup
# =============================================================================

.PHONY: clean
clean: ## Removes build artifacts (keeps the pinned tool cache)
	rm -rf bin/$(BIN) dist cover.out
	go clean ./...

.PHONY: clean-all
clean-all: clean ## Removes build artifacts and the pinned tool cache
	rm -rf $(TOOLS_DIR)

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help: ## Prints this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'
