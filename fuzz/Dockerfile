# Host fuzzers of the Ruby firmware in a container (for Windows / macOS; Linux can run
# fuzz/run.sh directly). Build from the REPO ROOT:
#
#   docker build -t ruby-fuzz -f fuzz/Dockerfile .
#   docker run --rm -v ruby-fuzz-out:/ruby/fuzz/out ruby-fuzz [SECONDS_PER_TARGET] [TARGET...]
#
# The named volume keeps the growing corpus (and any crash) between runs.
# Only the files listed in fuzz/Dockerfile.dockerignore are sent to the build.
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y clang make python3 git libmbedtls-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /ruby
COPY components/libwally-core components/libwally-core
COPY tests/rpc/data/sign_psbt tests/rpc/data/sign_psbt
COPY tests/codex32 tests/codex32
COPY libjade/include libjade/include
COPY main main
COPY fuzz fuzz
RUN make -s -C fuzz -j"$(nproc)" all

ENTRYPOINT ["sh", "fuzz/run.sh"]
CMD ["60"]
