//! Links the Go c-archive `libjuicefs-{os}-{arch}.a` built for this crate's version.
//!
//! The archive is looked for in three places, the first one that has it winning:
//! `target/juicefs`, where `task juicefs` installs it; `JUICEFS_CACHE`, for
//! anyone who keeps one; and `OUT_DIR`, where a download from release
//! `v{version}` lands, checked against `SHA256SUMS`.
//!
//! Finding none is a warning, not an error. `cargo check` never links, so it has
//! no use for the archive; a link that needs it fails on the missing library,
//! and the warning says what to do about it.

use std::env;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

const BASE_URL: &str = "https://github.com/xhebox/filesystem-rs/releases/download";

fn main() {
	println!("cargo:rerun-if-env-changed=JUICEFS_CACHE");

	let target_os = env::var("CARGO_CFG_TARGET_OS").expect("cargo sets CARGO_CFG_TARGET_OS");
	let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("cargo sets CARGO_CFG_TARGET_ARCH");
	let version = env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");
	let lib = format!("juicefs-{target_os}-{target_arch}");
	let name = format!("lib{lib}.a");
	let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"))
		.join(format!("v{version}"))
		.join(&name);

	// Named without the version: this is the workspace's own build, not a release.
	// It is watched even while absent, so that `task juicefs` makes cargo look again.
	let manifest =
		PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
	let local = manifest.join("../../target/juicefs").join(&name);
	println!("cargo:rerun-if-changed={}", local.display());

	let cached = env::var_os("JUICEFS_CACHE")
		.filter(|dir| !dir.is_empty())
		.map(|dir| PathBuf::from(dir).join(format!("v{version}")).join(&name));
	let archive = [Some(local), cached]
		.into_iter()
		.flatten()
		.chain([out.clone()])
		.find(|file| file.is_file())
		.or_else(|| match fetch(&version, &name, &out) {
			Ok(()) => Some(out),
			Err(reason) => {
				println!(
					"cargo:warning=juicefs-rs: {reason}; `task juicefs` builds it, and linking needs it"
				);
				None
			}
		});
	link(archive.as_deref(), &lib, &target_os);
}

/// Downloads `name` from release `v{version}` into `archive`, once its digest
/// matches the one `SHA256SUMS` gives it.
fn fetch(version: &str, name: &str, archive: &Path) -> Result<(), String> {
	let directory = format!("{BASE_URL}/v{version}");
	let sums = get(&format!("{directory}/SHA256SUMS"))?
		.read_to_string()
		.map_err(|error| error.to_string())?;
	let expected = expected_digest(&sums, name)
		.ok_or_else(|| format!("{directory}/SHA256SUMS has no line for {name}"))?;

	let parent = archive.parent().expect("the archive has a parent");
	fs::create_dir_all(parent)
		.map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
	// Unpacked beside the final name, so a half-written archive is never what a
	// later build finds.
	let part = parent.join(format!(".{name}.part"));
	let checked = unpack(&format!("{directory}/{name}.zst"), &part).and_then(|actual| {
		if actual == expected {
			return Ok(());
		}
		Err(format!("{name} hashes to {actual}, not {expected}"))
	});
	if let Err(reason) = checked {
		drop(fs::remove_file(&part));
		return Err(reason);
	}

	fs::rename(&part, archive)
		.map_err(|error| format!("cannot move {} into place: {error}", part.display()))
}

/// The digest `SHA256SUMS` gives `file`, in `sha256sum`'s format: a digest, two
/// spaces, a name — with `*` in front of the name for a binary-mode entry.
fn expected_digest(sums: &str, file: &str) -> Option<String> {
	sums.lines().find_map(|line| {
		let mut fields = line.split_whitespace();
		let digest = fields.next()?;
		let name = fields.next()?;
		(name.trim_start_matches('*') == file).then(|| digest.to_string())
	})
}

/// Opens `url` for reading. The timeout covers the whole transfer.
fn get(url: &str) -> Result<ureq::Body, String> {
	let config = ureq::Agent::config_builder()
		.timeout_global(Some(Duration::from_secs(600)))
		.build();
	let response = ureq::Agent::new_with_config(config)
		.get(url)
		.call()
		.map_err(|error| format!("cannot download {url} ({error})"))?;
	Ok(response.into_body())
}

/// Streams `url` through the decompressor into `part`, and returns the digest of
/// what was written. Hashing on the way means the archive is never read twice,
/// and never has to sit in memory beside the several times larger thing it
/// unpacks to.
fn unpack(url: &str, part: &Path) -> Result<String, String> {
	let mut decoder = ruzstd::decoding::StreamingDecoder::new(get(url)?.into_reader())
		.map_err(|error| format!("not one zstd frame: {error}"))?;
	let file = File::create(part).map_err(|error| error.to_string())?;
	let mut hashing = Hashing {
		file: BufWriter::new(file),
		hasher: Sha256::new(),
	};
	io::copy(&mut decoder, &mut hashing).map_err(|error| error.to_string())?;
	hashing.flush().map_err(|error| error.to_string())?;
	Ok(hashing
		.hasher
		.finalize()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect())
}

/// Writes through to `file`, hashing every byte that gets written.
struct Hashing<W> {
	file: W,
	hasher: Sha256,
}

impl<W: Write> Write for Hashing<W> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		let written = self.file.write(buf)?;
		self.hasher.update(&buf[..written]);
		Ok(written)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.file.flush()
	}
}

/// Tells rustc where the archive is, if there is one, and what its C half needs
/// beyond libc. Without an archive the library is still named, so the link
/// fails on it rather than on something further off.
fn link(archive: Option<&Path>, lib: &str, target_os: &str) {
	if let Some(archive) = archive {
		// Cargo relinks only for a dependency it was told about.
		println!("cargo:rerun-if-changed={}", archive.display());

		let dir = archive.parent().expect("the archive has a parent");
		println!("cargo:rustc-link-search=native={}", dir.display());
	}
	// MSVC's linker looks for `{lib}.lib` under `static={lib}`, and nothing else, so
	// on Windows the archive is named as it is, with `+verbatim`.
	if target_os == "windows" {
		println!("cargo:rustc-link-lib=static:+verbatim=lib{lib}.a");
	} else {
		println!("cargo:rustc-link-lib=static={lib}");
	}

	// On musl these are all in libc, and Rust links it statically for musl
	// targets, so naming them there would only look for files that do not exist.
	let system: &[&str] = match target_os {
		"linux" if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") => &[],
		"linux" => &["pthread", "dl", "m"],
		// Go's `crypto/x509` reaches into these on macOS.
		"macos" => &["framework=Security", "framework=CoreFoundation"],
		// Go's Windows runtime and cgo's MinGW objects call into these directly;
		// `legacy_stdio_definitions` supplies the `fprintf` symbol UCRT inline-wrapped.
		"windows" => &[
			"advapi32",
			"legacy_stdio_definitions",
			"ntdll",
			"userenv",
			"ws2_32",
		],
		_ => &[],
	};
	for lib in system {
		println!("cargo:rustc-link-lib={lib}");
	}

	// `legacy_stdio_definitions.lib` carries two `.drectve` sections that disagree
	// about their attributes; link.exe's LNK4078 for it is noise, and the
	// workspace links with `-D warnings`.
	if target_os == "windows" {
		println!("cargo:rustc-link-arg=/ignore:4078");
	}
}
