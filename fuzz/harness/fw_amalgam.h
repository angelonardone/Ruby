#ifndef FUZZ_FW_AMALGAM_H_
#define FUZZ_FW_AMALGAM_H_

// The firmware is ONE translation unit (main/amalgamated.c): libwally's amalgamation (combined.c) first, then every
// firmware file. Some firmware code relies on that: it calls libwally functions that only that unit sees (eg.
// wally_psbt_get_input_best_utxo) and headers included by an earlier file. A harness of firmware code does the
// same: it includes this header first, then the firmware .c files it tests. Such a harness is listed in FW_TARGETS
// of the Makefile (it is not linked with build/wally.o, which would define libwally twice).
//
// libwally is built with the defines of amalgamated.c / components/libwally-core/CMakeLists.txt (the Makefile's
// WALLY_DEFS); ESP-IDF / FreeRTOS come from libjade/include.

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#include "../../components/libwally-core/upstream/src/amalgamation/combined.c"
#pragma clang diagnostic pop

#include "utils/malloc_ext.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#ifndef pdMS_TO_TICKS
// Used by musig2.c, missing from libjade/include (portTICK_PERIOD_MS is 1 there)
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms) / portTICK_PERIOD_MS)
#endif

#endif /* FUZZ_FW_AMALGAM_H_ */
