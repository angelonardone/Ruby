#!/bin/sh
# Build and run Ruby's host fuzzers. See fuzz/README.md.
#
#   fuzz/run.sh [SECONDS_PER_TARGET] [TARGET...]
#
# For every target: first replay fuzz/regressions/<target>/* (must all pass), then
# fuzz for SECONDS_PER_TARGET (default 60) starting from the generated seeds, the
# hand-made seeds in fuzz/corpus/<target>/ and the corpus kept in $FUZZ_OUT.
#
# Output ($FUZZ_OUT, default fuzz/out/, never committed):
#   corpus/<target>/   inputs that reached new code (reused by the next run)
#   crashes/<target>/  inputs that crashed (crash-*, leak-*, timeout-*, oom-*)
#   logs/<target>.log  full libFuzzer + sanitizer output
#
# When CI=true the sanitizer reports are NOT printed (this repo is public: a crash
# report is an exploit hint); only the target, the crash kind and the libFuzzer seed.
# Set FUZZ_VERBOSE=1 to print the end of the log anyway.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SECS=${1:-60}
[ $# -gt 0 ] && shift
OUT=${FUZZ_OUT:-$HERE/out}
BUILD=$HERE/build
JOBS=$(nproc 2>/dev/null || echo 2)
CI=${CI:-false}
VERBOSE=${FUZZ_VERBOSE:-$([ "$CI" = true ] && echo 0 || echo 1)}
# Known, unreachable-on-Ruby library bugs (each one documented in the file).
export LSAN_OPTIONS=${LSAN_OPTIONS:-suppressions=$HERE/known-issues.supp:print_suppressions=0}

make -s -C "$HERE" ROOT="$ROOT" BUILD="$BUILD" -j"$JOBS" all
rm -rf "$BUILD/seeds"
python3 "$HERE/tools/make_seeds.py" "$ROOT" "$BUILD/seeds"

if [ $# -gt 0 ]; then
    TARGETS="$*"
else
    TARGETS=$(make -s -C "$HERE" ROOT="$ROOT" list)
fi

show_log() {
    if [ "$VERBOSE" = 1 ]; then
        tail -n 60 "$1"
    else
        echo "    (log hidden: see fuzz/README.md, 'Crashes in a public repo')"
    fi
}

failed=""
for t in $TARGETS; do
    bin=$BUILD/$t
    log=$OUT/logs/$t.log
    mkdir -p "$OUT/corpus/$t" "$OUT/crashes/$t" "$OUT/logs"

    reg=$HERE/regressions/$t
    if [ -d "$reg" ] && [ -n "$(ls -A "$reg" 2>/dev/null | grep -v '^README')" ]; then
        if ! "$bin" $(ls -d "$reg"/* | grep -v '/README') >"$OUT/logs/$t.regressions.log" 2>&1; then
            echo "FAIL $t: a regression input crashes again"
            show_log "$OUT/logs/$t.regressions.log"
            failed="$failed $t"
            continue
        fi
    fi

    dirs="$OUT/corpus/$t $BUILD/seeds/$t"
    [ -d "$HERE/corpus/$t" ] && dirs="$dirs $HERE/corpus/$t"
    # -rss_limit_mb / -timeout: the device has ~130 KB of free heap; anything slow or
    # huge on a PC is already a bug on Ruby.
    if "$bin" -max_total_time="$SECS" -timeout=10 -rss_limit_mb=2048 \
            -artifact_prefix="$OUT/crashes/$t/" -print_final_stats=1 $dirs >"$log" 2>&1; then
        runs=$(grep -m1 'stat::number_of_executed_units' "$log" | awk '{print $2}')
        cov=$(grep -E '^#[0-9]+.*cov:' "$log" | tail -n1 | sed -E 's/.*cov: ([0-9]+).*/\1/')
        echo "PASS $t: ${runs:-?} runs in ${SECS}s, coverage ${cov:-?} edges, corpus $(ls "$OUT/corpus/$t" | wc -l) inputs"
    else
        kind=$(grep -m1 -oE 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|libFuzzer): [a-z-]+' "$log" || true)
        [ -z "$kind" ] && kind=$(grep -m1 -oE 'runtime error' "$log" || echo "crash")
        seed=$(grep -m1 -oE 'Seed: [0-9]+' "$log" || true)
        echo "FAIL $t: $kind ($seed); input saved in $OUT/crashes/$t/"
        show_log "$log"
        failed="$failed $t"
    fi
done

if [ -n "$failed" ]; then
    echo "Fuzzing FAILED:$failed"
    exit 1
fi
echo "Fuzzing passed: $TARGETS"
