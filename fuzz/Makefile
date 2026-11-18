# Host fuzzers for the Ruby firmware (clang + libFuzzer + ASan/UBSan).
# See fuzz/README.md. Normally driven by fuzz/run.sh.
#
#   make -C fuzz all          build every target into fuzz/build/
#   make -C fuzz list         print the target names
#
# libwally is compiled exactly as components/libwally-core/CMakeLists.txt does for
# the device (the amalgamation with the same defines), except that mbedTLS SHA is
# not used (no ESP-IDF here: libwally's own SHA code is used instead) and the
# compiler is clang with sanitizers instead of xtensa-esp32-elf-gcc.

ROOT  ?= ..
BUILD ?= build
CC    := clang

WALLY := $(ROOT)/components/libwally-core
UP    := $(WALLY)/upstream
SECP  := $(UP)/src/secp256k1

SAN    ?= -fsanitize=address,undefined -fno-sanitize-recover=undefined
CFLAGS ?= -g -O1 -fno-omit-frame-pointer

# Same as components/libwally-core/CMakeLists.txt (minus HAVE_MBEDTLS_SHA*_H).
WALLY_DEFS := -DBUILD_MINIMAL=1 -DHAVE_EXPLICIT_BZERO=1 -DNDEBUG=1 \
              -DECMULT_WINDOW_SIZE=8 -DHAVE_BUILTIN_POPCOUNT=1 \
              -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_ECDSA_S2C=1 \
              -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_MUSIG=1 \
              -DENABLE_MODULE_RECOVERY=1 -DENABLE_MODULE_SCHNORRSIG=1
# Ruby's config.h says HAVE_UNALIGNED_ACCESS=1, so ccan's SHA-256/512/RIPEMD-160 read
# uint32_t words from unaligned input, which UBSan reports. On the device SHA-256/512 are
# mbedTLS (not this code); libwally offers AVOID_UNALIGNED_ACCESS for sanitizer builds.
# See fuzz/README.md, "libwally as on the device".
WALLY_DEFS += -DAVOID_UNALIGNED_ACCESS=1
WALLY_INC  := -I$(WALLY) -I$(UP) -I$(UP)/src -I$(UP)/include -I$(UP)/src/ccan \
              -I$(SECP) -I$(SECP)/src -I$(SECP)/include

# Targets taken unchanged from libwally (components/libwally-core/upstream/fuzz/).
LIBWALLY_TARGETS := fuzz_psbt_from_bytes fuzz_tx_from_bytes
# Ruby's own harnesses (fuzz/harness/<name>.c), added in later steps.
RUBY_TARGETS     := $(basename $(notdir $(wildcard harness/*.c)))

TARGETS := $(LIBWALLY_TARGETS) $(RUBY_TARGETS)

.PHONY: all list clean
all: $(addprefix $(BUILD)/,$(TARGETS))

list:
	@echo $(TARGETS)

$(BUILD):
	mkdir -p $@

# libwally + libsecp256k1-zkp, instrumented for coverage but without libFuzzer's main().
$(BUILD)/wally.o: $(UP)/src/amalgamation/combined.c | $(BUILD)
	$(CC) $(CFLAGS) $(SAN) -fsanitize=fuzzer-no-link -w $(WALLY_DEFS) $(WALLY_INC) -c $< -o $@

# libwally's harnesses call malloc() without including <stdlib.h>.
$(BUILD)/fuzz_%: $(UP)/fuzz/fuzz_%.c $(BUILD)/wally.o
	$(CC) $(CFLAGS) $(SAN) -fsanitize=fuzzer -include stdlib.h -I$(UP)/include $< $(BUILD)/wally.o -o $@

$(BUILD)/%: harness/%.c $(BUILD)/wally.o
	$(CC) $(CFLAGS) $(SAN) -fsanitize=fuzzer $(WALLY_DEFS) $(WALLY_INC) -Iharness -Istubs $< $(BUILD)/wally.o -o $@

clean:
	rm -rf $(BUILD)
