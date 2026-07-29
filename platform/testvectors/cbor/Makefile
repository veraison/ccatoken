# Copyright 2024-2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0
# NOTE: the notion of which test vectors will be built is encoded in
#       build-test-vectors.sh

OUTPUT := ../../pretty_test_vectors.go

DEPS := $(wildcard *.diag v2/*.diag)

all: $(OUTPUT)

$(OUTPUT): $(DEPS)
	env TV_DOT_GO=$(OUTPUT) ./build-test-vectors.sh

clean: ; $(RM) $(OUTPUT)
