// Host stand-ins for firmware functions, for the harnesses that compile real firmware files (fuzz/README.md,
// "Firmware code on the host"). ESP-IDF / FreeRTOS themselves come from libjade/include (Jade's own host shims).
//
// - jade_abort, get_random, sensitive_push / sensitive_pop: behave like the firmware's (sensitive.c keeps its
//   checks: at most 32 items, popped in LIFO order, every popped buffer wiped).
// - Everything else here (processes, screens, keychain, storage) is code the fuzzed functions must NOT reach:
//   it aborts, so a harness that reaches it fails loudly instead of testing a fake. These are weak: a harness that
//   needs one of them (eg. a test wallet for keychain_get) defines it, copied from the firmware.
#include "firmware_stubs.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_crypto.h>

#define NOT_REACHED(name)                                                                                              \
    do {                                                                                                               \
        fprintf(stderr, "fuzz stub: %s must not be reached\n", name);                                                 \
        abort();                                                                                                       \
    } while (0)

// ---- jade_assert.h ----

__attribute__((__noreturn__)) void jade_abort(const char* file, const int line_n)
{
    fprintf(stderr, "jade_abort at %s:%d\n", file, line_n);
    abort();
}

// ---- random.h ----

// SplitMix64 seeded from the input: reproducible for a given input, yet never degenerate (the firmware's TRNG does
// not return 4 invalid private keys in a row, so neither must this; an all-zero stream would make
// keychain_get_new_privatekey fail and look like a bug)
static uint64_t rnd_state;

void fuzz_random_set(const uint8_t* data, const size_t len)
{
    uint64_t h = 0xcbf29ce484222325ULL; // FNV-1a
    for (size_t i = 0; i < len; ++i) {
        h = (h ^ data[i]) * 0x100000001b3ULL;
    }
    rnd_state = h ^ len;
}

static uint64_t splitmix64(void)
{
    uint64_t z = (rnd_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

void get_random(void* bytes_out, const size_t len)
{
    uint8_t* out = bytes_out;
    for (size_t i = 0; i < len; i += 8) {
        const uint64_t r = splitmix64();
        for (size_t b = 0; b < 8 && i + b < len; ++b) {
            out[i + b] = (uint8_t)(r >> (8 * b));
        }
    }
}

// ---- sensitive.h (as main/sensitive.c, with one stack: the harnesses are single-threaded) ----

#define SENS_STACK_SIZE 32

static struct {
    void* addr;
    size_t size;
} sens[SENS_STACK_SIZE];
static size_t sens_top;

void sensitive_push(const char* file, int line, void* addr, size_t size)
{
    if (sens_top + 1 >= SENS_STACK_SIZE) {
        fprintf(stderr, "sensitive_push %s:%d: sensitive stack exhausted\n", file, line);
        abort();
    }
    sens[sens_top].addr = addr;
    sens[sens_top].size = size;
    ++sens_top;
}

void sensitive_pop(const char* file, int line, void* addr)
{
    if (!sens_top) {
        fprintf(stderr, "sensitive_pop %s:%d: stack empty\n", file, line);
        abort();
    }
    --sens_top;
    memset(sens[sens_top].addr, 0, sens[sens_top].size);
    if (addr != sens[sens_top].addr) {
        fprintf(stderr, "sensitive_pop %s:%d: popping %p, top is %p\n", file, line, addr, sens[sens_top].addr);
        abort();
    }
}

size_t fuzz_sensitive_depth(void) { return sens_top; }

// ---- keychain.c: keychain_get_new_privatekey, as in the firmware (from get_random above) ----

bool keychain_get_new_privatekey(uint8_t* privatekey, const size_t size)
{
    if (!privatekey || size != EC_PRIVATE_KEY_LEN) {
        return false;
    }
    for (size_t attempts = 0; attempts < 4; ++attempts) {
        get_random(privatekey, size);
        if (wally_ec_private_key_verify(privatekey, size) == WALLY_OK) {
            return true;
        }
    }
    return false;
}

// ---- utils/temporary_stack.h: run the function on this (host) stack ----

typedef bool (*temporary_stack_function_t)(void*);
bool run_in_temporary_task(const size_t stack_size, temporary_stack_function_t fn, void* ctx)
{
    (void)stack_size;
    return fn(ctx);
}

// ---- FreeRTOS ticks (musig2.c: lifetime of the kept nonces) ----

static uint32_t fuzz_ticks;
uint32_t xTaskGetTickCount(void) { return ++fuzz_ticks; }
unsigned int uxTaskGetStackHighWaterMark(void* task)
{
    (void)task;
    return 0;
}

// ---- processes, screens, keychain, wallet: not reached by the fuzzed functions ----

__attribute__((weak)) void is_potential_green_server_path(void) { NOT_REACHED("is_potential_green_server_path"); }
__attribute__((weak)) void is_potential_green_user_path(void) { NOT_REACHED("is_potential_green_user_path"); }

__attribute__((weak)) void jade_process_free_on_exit(void) { NOT_REACHED("jade_process_free_on_exit"); }
__attribute__((weak)) void jade_process_load_in_message(void) { NOT_REACHED("jade_process_load_in_message"); }
__attribute__((weak)) void jade_process_reject_message(void) { NOT_REACHED("jade_process_reject_message"); }
__attribute__((weak)) void jade_process_reply_to_message_bytes(void) { NOT_REACHED("jade_process_reply_to_message_bytes"); }
__attribute__((weak)) void jade_process_reply_to_message_bytes_sequence(void) { NOT_REACHED("jade_process_reply_to_message_bytes_sequence"); }
__attribute__((weak)) void jade_process_reply_to_message_ok(void) { NOT_REACHED("jade_process_reply_to_message_ok"); }
__attribute__((weak)) void check_extended_data_fields(void) { NOT_REACHED("check_extended_data_fields"); }
__attribute__((weak)) void display_processing_message_activity(void) { NOT_REACHED("display_processing_message_activity"); }
__attribute__((weak)) void show_restore_seed_activity(void) { NOT_REACHED("show_restore_seed_activity"); }
__attribute__((weak)) void show_seed_split_activity(void) { NOT_REACHED("show_seed_split_activity"); }
__attribute__((weak)) void keychain_clear_network_type_restriction(void) { NOT_REACHED("keychain_clear_network_type_restriction"); }
__attribute__((weak)) void keychain_derive_from_seed(void) { NOT_REACHED("keychain_derive_from_seed"); }
__attribute__((weak)) void keychain_get(void) { NOT_REACHED("keychain_get"); }
__attribute__((weak)) void keychain_get_userdata(void) { NOT_REACHED("keychain_get_userdata"); }
__attribute__((weak)) void keychain_has_pin(void) { NOT_REACHED("keychain_has_pin"); }
__attribute__((weak)) void keychain_has_temporary(void) { NOT_REACHED("keychain_has_temporary"); }
__attribute__((weak)) void keychain_set(void) { NOT_REACHED("keychain_set"); }
__attribute__((weak)) void await_error(void) { NOT_REACHED("await_error"); }
__attribute__((weak)) void jade_process_check_network(void) { NOT_REACHED("jade_process_check_network"); }
__attribute__((weak)) void show_register_group_activity(void) { NOT_REACHED("show_register_group_activity"); }
__attribute__((weak)) void storage_get_group_registration(void) { NOT_REACHED("storage_get_group_registration"); }
__attribute__((weak)) void storage_get_group_registration_count(void) { NOT_REACHED("storage_get_group_registration_count"); }
__attribute__((weak)) void storage_group_name_exists(void) { NOT_REACHED("storage_group_name_exists"); }
__attribute__((weak)) void storage_has_room_for_blob(void) { NOT_REACHED("storage_has_room_for_blob"); }
__attribute__((weak)) void storage_set_group_registration(void) { NOT_REACHED("storage_set_group_registration"); }
__attribute__((weak)) void storage_key_name_valid(void) { NOT_REACHED("storage_key_name_valid"); }
__attribute__((weak)) void wallet_get_hdkey(void) { NOT_REACHED("wallet_get_hdkey"); }
__attribute__((weak)) void wallet_hmac_with_master_key(void) { NOT_REACHED("wallet_hmac_with_master_key"); }
