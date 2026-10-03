.DEFAULT_GOAL := test

export GO111MODULE := on
export SHELL := /bin/bash

GOPKG := github.com/veraison/ccatoken
GOPKG += github.com/veraison/ccatoken/platform
GOPKG += github.com/veraison/ccatoken/realm

GOLINT ?= golangci-lint

GOLINT_ARGS ?= run

.PHONY: lint
lint: ; $(GOLINT) $(GOLINT_ARGS)

ifeq ($(MAKECMDGOALS),test)
GOTEST_ARGS ?= -v -race $(GOPKG)
else
  ifeq ($(MAKECMDGOALS),test-cover)
  GOTEST_ARGS ?= -short -cover $(GOPKG)
  endif
endif

COVER_THRESHOLD := $(shell sed -n "s/^ *min-coverage: '\(.*\)'/≥\1%/p" .github/workflows/ci-go-cover.yml)

.PHONY: test test-cover
test test-cover: ; go test $(GOTEST_ARGS)

presubmit:
	@echo
	@echo ">>> Check that the reported coverage figures are $(COVER_THRESHOLD)"
	@echo
	$(MAKE) test-cover
	@echo
	@echo ">>> Fix any lint error"
	@echo
	$(MAKE) lint

.PHONY: licenses
licenses: ; @./scripts/licenses.sh

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  * test:       run unit tests for $(GOPKG)"
	@echo "  * test-cover: run unit tests and measure coverage for $(GOPKG)"
	@echo "  * lint:       lint sources using .golangci.yml"
	@echo "  * presubmit:  check you are ready to push your local branch to remote"
	@echo "  * help:       print this menu"
