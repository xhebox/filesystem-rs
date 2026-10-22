# The JuiceFS c-archive juicefs-rs links, for Linux. Build it with this directory
# as the context:
#
#   docker build --target artifact --output type=local,dest=DIR crates/juicefs-rs
#
# writes libjuicefs-linux-<arch>.a into DIR, under the name juicefs-rs's build.rs
# looks for. Nothing else is written to the host.
#
# The build stage is Alpine, whose `cc` is musl's: the archive is linked into a
# musl-static binary, and cgo's C half (SQLite included) has to be the same libc
# as the rest of the process.
#
# Go's module and build caches are BuildKit cache mounts, so after an edit only
# what changed is compiled again.

FROM golang:1.25-alpine AS build
RUN apk add --no-cache build-base binutils

WORKDIR /src
COPY binding .
# `-ldflags=-w` keeps DWARF out: Go compresses it with zlib, and the `rust-lld`
# these targets link with cannot read that. `asyncpreemptoff=1` turns off
# `SIGURG`-driven preemption so a second Go archive in the same process cannot
# swallow this runtime's preemption signal.
#
# The archive's objects are then partially linked into one `juicefs.o` with its
# `.init_array` constructor removed, its `_rt0_*_lib` entry renamed to
# `juicefs_rt0`, and every symbol outside `juicefs_*` localized so neither the
# Go/cgo bridge (`crosscall2`, `x_cgo_*`) nor C dependencies (`sqlite3_*`,
# `ZSTD_*`, `LZ4_*`) can collide with the host or with another Go archive.
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	mkdir -p /out \
	&& CGO_ENABLED=1 go build -buildmode=c-archive -trimpath \
		-ldflags="-w -X=runtime.godebugDefault=asyncpreemptoff=1" \
		-tags=netgo,osusergo,nogspt -o /out/libjuicefs.a . \
	&& objcopy --remove-section=.init_array \
		--redefine-sym "_rt0_$(go env GOARCH)_linux_lib=juicefs_rt0" \
		--globalize-symbol=juicefs_rt0 \
		/out/libjuicefs.a \
	&& ld -r -dc --whole-archive /out/libjuicefs.a -o /out/juicefs.o \
	&& objcopy --strip-debug --wildcard --keep-global-symbol='juicefs_*' \
		/out/juicefs.o \
	&& ar rcs "/out/libjuicefs-linux-$(uname -m).a" /out/juicefs.o

# The last stage is what --output exports, so it holds only the archive.
FROM scratch AS artifact
COPY --from=build /out/libjuicefs-*.a /
