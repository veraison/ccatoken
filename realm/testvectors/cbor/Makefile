# NOTE: the notion of which test vectors will be built is encoded in
#       build-test-vectors.sh

OUTPUT := ../../pretty_test_vectors.go

DEPS := $(wildcard *.diag)

all: $(OUTPUT)

$(OUTPUT): $(DEPS)
	env TV_DOT_GO=$(OUTPUT) ./build-test-vectors.sh

clean: ; $(RM) $(OUTPUT)
