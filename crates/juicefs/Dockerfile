# The JuiceFS c-archive boxfs-juicefs links, for Linux and Android. Build it
# with this directory as the context:
#
#   docker build --target artifact --output type=local,dest=DIR crates/juicefs
#
# writes libjuicefs-linux-<arch>.a into DIR (or libjuicefs-android-aarch64.a
# with `--build-arg TARGET_OS=android`), under the name boxfs-juicefs's
# build.rs looks for. Nothing else is written to the host.
#
# Go's module and build caches are BuildKit cache mounts, so after an edit only
# what changed is compiled again.

ARG TARGET_OS=linux

# The Linux build stage is Alpine, whose `cc` is musl's: the archive is linked
# into a musl-static binary, and cgo's C half (SQLite included) has to be the
# same libc as the rest of the process.
FROM golang:1.25-alpine AS build-linux
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

# Go's platform table rejects `-buildmode=c-archive` for `GOOS=android`, so the
# archive is built as `GOOS=linux GOARCH=arm64` with the Android NDK's clang and
# LLVM binutils. An overlay switches `runtime/tls_arm64.s` onto its Android
# `TLS_SLOT_APP` branch (`DATA runtime.tls_g = 16`, `NOPTR`) so the archive
# carries no initial-exec `.tbss` relocations that Bionic's `dlopen` rejects.
FROM golang:1.25-bookworm AS build-android
RUN apt-get update && apt-get install -y --no-install-recommends unzip \
	&& rm -rf /var/lib/apt/lists/* \
	&& wget -q https://dl.google.com/android/repository/android-ndk-r26d-linux.zip -O /tmp/ndk.zip \
	&& unzip -q /tmp/ndk.zip -d / \
	&& mv /android-ndk-r26d /android-ndk \
	&& rm /tmp/ndk.zip
ENV PATH="/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:${PATH}"

WORKDIR /src
COPY binding .
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	ln -sf /android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar /usr/local/bin/ar \
	&& sed -e 's/#ifdef TLSG_IS_VARIABLE/#ifdef GOOS_linux/' \
		-e 's/#ifdef GOOS_android/#ifdef GOOS_linux/' \
		/usr/local/go/src/runtime/tls_arm64.s > /tmp/tls_arm64.s \
	&& printf '{"Replace":{"/usr/local/go/src/runtime/tls_arm64.s":"/tmp/tls_arm64.s"}}\n' > /tmp/overlay.json \
	&& mkdir -p /out \
	&& CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
		CC=aarch64-linux-android34-clang \
		AR=llvm-ar \
		go build -overlay=/tmp/overlay.json -buildmode=c-archive -trimpath \
		-ldflags="-w -X=runtime.godebugDefault=asyncpreemptoff=1" \
		-tags=netgo,osusergo,nogspt -o /out/libjuicefs.a . \
	&& llvm-objcopy --remove-section=.init_array \
		--redefine-sym "_rt0_arm64_linux_lib=juicefs_rt0" \
		/out/libjuicefs.a \
	&& ld.lld -r --whole-archive /out/libjuicefs.a -o /out/juicefs.o \
	&& llvm-objcopy --strip-debug --globalize-symbol=juicefs_rt0 \
		--wildcard --keep-global-symbol='juicefs_*' \
		/out/juicefs.o \
	&& llvm-ar rcs /out/libjuicefs-android-aarch64.a /out/juicefs.o

FROM build-${TARGET_OS} AS selected

# The last stage is what --output exports, so it holds only the archive.
FROM scratch AS artifact
COPY --from=selected /out/libjuicefs-*.a /
