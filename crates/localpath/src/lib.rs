//! A host directory served as a FUSE file system, confined to that directory.
//!
//! [`PassthroughFs`] implements [`api::Fuse`], [`api::Volume`], and
//! [`api::Snapshot`] over a directory the
//! caller opened. Every name is resolved beneath that directory's descriptor,
//! so nothing a guest names can reach past it. The request protocol, dispatch
//! and reply encoding belong to whoever drives the file system; this crate is
//! the back-end they call.
//!
//! Each supported host OS has its own self-contained module (`linux`,
//! `macos`, `windows`); on other targets the crate is empty.

#![cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]

mod abi;
mod span;

std::cfg_select! {
	target_os = "linux" => {
		mod linux;
		use linux as imp;
	}
	target_os = "macos" => {
		mod macos;
		use macos as imp;
	}
	target_os = "windows" => {
		mod windows;
		use windows as imp;
	}
}

pub use imp::PassthroughFs;

#[cfg(all(test, unix))]
mod tests;
