#!/bin/sh
# Builds and runs the host test of main/codex32.c, then checks its random splits with the BIP-93 Python reference.
# Run from this directory (Linux / macOS / a container). With Docker, from the REPO ROOT:
#   docker run --rm -v "$PWD":/ruby -w /ruby/tests/codex32 ubuntu:24.04 sh -c \
#     "apt-get update -qq && apt-get install -y -qq clang python3 >/dev/null && sh run.sh"
set -e
CC=${CC:-clang}
$CC -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=all -I../../main \
    -o /tmp/test_codex32 test_codex32.c ../../main/codex32.c
/tmp/test_codex32 /tmp/codex32_cases.json
python3 -I codex32_reference.py /tmp/codex32_cases.json
