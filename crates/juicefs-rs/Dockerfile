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
# these targets link with cannot read that. objcopy then takes out the Go
# runtime's library constructor, which has no argc/argv to start from: the
# entry it calls is globalized so juicefs-rs can call it with the process's own.
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	mkdir -p /out \
	&& CGO_ENABLED=1 go build -buildmode=c-archive -trimpath -ldflags=-w \
		-tags=netgo,osusergo,nogspt -o /out/libjuicefs.a . \
	&& objcopy --strip-debug --remove-section=.init_array \
		--globalize-symbol="_rt0_$(go env GOARCH)_linux_lib" /out/libjuicefs.a \
	&& mv /out/libjuicefs.a "/out/libjuicefs-linux-$(uname -m).a"

# The last stage is what --output exports, so it holds only the archive.
FROM scratch AS artifact
COPY --from=build /out/libjuicefs-*.a /
