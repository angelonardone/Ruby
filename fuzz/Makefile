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

# Firmware code on the host (fuzz/README.md): ESP-IDF / FreeRTOS from Jade's libjade/include shims, tinycbor
# 0.6.1 (the exact sources of the firmware's espressif/cbor 0.6.1~4, same CBOR_PARSER_MAX_RECURSIONS), the
# firmware's utils/cbor_rpc.c, and stubs/firmware_stubs.c for what the fuzzed code must not reach.
# CONFIG_LIBJADE_NO_SPIRAM: message sizes of the reference board (M5Stack Basic, no PSRAM).
TINYCBOR        ?= $(BUILD)/tinycbor
TINYCBOR_COMMIT := c0aad2fb2137a31b9845fbaae3653540c410f215
TINYCBOR_SRCS   := cborencoder cborencoder_close_container_checked cborencoder_float cborerrorstrings \
                   cborparser cborparser_dup_string cborparser_float cborvalidation
FW_DEFS := -DCONFIG_LOG_DEFAULT_LEVEL_NONE -DLIBJADE_BUILD -DCONFIG_LIBJADE_NO_SPIRAM \
           -DCBOR_PARSER_MAX_RECURSIONS=20
FW_INC  := -I$(ROOT)/libjade/include -I$(ROOT)/main -I$(TINYCBOR)/src -Istubs
FW_OBJS := $(BUILD)/cbor_rpc.o $(BUILD)/firmware_stubs.o $(BUILD)/tinycbor.a
FW_LIBS := -lmbedcrypto

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

# tinycbor at the commit of tag v0.6.1, fetched once (git) unless TINYCBOR points to a copy.
$(TINYCBOR)/src/cbor.h:
	rm -rf $(TINYCBOR)
	git clone -q https://github.com/intel/tinycbor.git $(TINYCBOR)
	git -C $(TINYCBOR) checkout -q $(TINYCBOR_COMMIT)

$(BUILD)/tinycbor.a: $(TINYCBOR)/src/cbor.h | $(BUILD)
	mkdir -p $(BUILD)/tinycbor-obj
	for f in $(TINYCBOR_SRCS); do \
	  $(CC) $(CFLAGS) $(SAN) -fsanitize=fuzzer-no-link -w -DCBOR_PARSER_MAX_RECURSIONS=20 -I$(TINYCBOR)/src \
	    -c $(TINYCBOR)/src/$$f.c -o $(BUILD)/tinycbor-obj/$$f.o || exit 1; done
	ar rcs $@ $(BUILD)/tinycbor-obj/*.o

$(BUILD)/cbor_rpc.o: $(ROOT)/main/utils/cbor_rpc.c $(TINYCBOR)/src/cbor.h | $(BUILD)
	$(CC) $(CFLAGS) $(SAN) -fsanitize=fuzzer-no-link $(FW_DEFS) $(FW_INC) $(WALLY_INC) -c $< -o $@

$(BUILD)/firmware_stubs.o: stubs/firmware_stubs.c stubs/firmware_stubs.h | $(BUILD)
	$(CC) $(CFLAGS) $(SAN) $(WALLY_INC) -c $< -o $@

# Harnesses of firmware code: one translation unit with libwally's combined.c, as main/amalgamated.c
# (harness/fw_amalgam.h), so they are not linked with build/wally.o.
FW_TARGETS := fuzz_restore_seed fuzz_seed_split fuzz_psbt_taproot fuzz_register_group fuzz_musig2_session

$(addprefix $(BUILD)/,$(FW_TARGETS)): $(BUILD)/%: harness/%.c $(FW_OBJS)
	$(CC) $(CFLAGS) $(SAN) -fsanitize=fuzzer -MMD -MP $(WALLY_DEFS) $(FW_DEFS) $(FW_INC) $(WALLY_INC) -Iharness $< \
	  $(FW_OBJS) $(FW_LIBS) -o $@

# Other harnesses: linked with build/wally.o
$(BUILD)/%: harness/%.c $(BUILD)/wally.o $(FW_OBJS)
	$(CC) $(CFLAGS) $(SAN) -fsanitize=fuzzer -MMD -MP $(WALLY_DEFS) $(FW_DEFS) $(FW_INC) $(WALLY_INC) -Iharness $< \
	  $(BUILD)/wally.o $(FW_OBJS) $(FW_LIBS) -o $@

# Rebuild a harness when a firmware file or header it includes changes
-include $(wildcard $(BUILD)/*.d)

clean:
	rm -rf $(BUILD)
