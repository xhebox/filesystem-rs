//! Compact binary state codec for [`PassthroughFs`](crate::PassthroughFs)
//! snapshot/restore across hosts.

use std::io;

const MAGIC: &[u8; 8] = b"BXLP\x01\0\0\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SavedNode {
	pub(crate) id: u64,
	pub(crate) parent: u64,
	pub(crate) lookups: u64,
	pub(crate) file_type: u32,
	pub(crate) path: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SavedHandle {
	pub(crate) handle: u64,
	pub(crate) inode: u64,
	pub(crate) is_dir: bool,
	pub(crate) flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SavedState {
	pub(crate) next_inode: u64,
	pub(crate) next_handle: u64,
	pub(crate) nodes: Vec<SavedNode>,
	pub(crate) handles: Vec<SavedHandle>,
}

pub(crate) fn encode(state: &SavedState) -> io::Result<Vec<u8>> {
	let node_count = u32::try_from(state.nodes.len())
		.map_err(|_| invalid("too many cached inodes to snapshot"))?;
	let handle_count = u32::try_from(state.handles.len())
		.map_err(|_| invalid("too many open handles to snapshot"))?;

	let mut out = Vec::with_capacity(32 + state.nodes.len() * 48 + state.handles.len() * 24);
	out.extend_from_slice(MAGIC);
	out.extend_from_slice(&state.next_inode.to_le_bytes());
	out.extend_from_slice(&state.next_handle.to_le_bytes());
	out.extend_from_slice(&node_count.to_le_bytes());
	out.extend_from_slice(&handle_count.to_le_bytes());

	for node in &state.nodes {
		if node.path.is_empty() {
			return Err(invalid("saved non-root inode has empty relative path"));
		}
		let comp_count = u32::try_from(node.path.len())
			.map_err(|_| invalid("inode path has too many components"))?;
		out.extend_from_slice(&node.id.to_le_bytes());
		out.extend_from_slice(&node.parent.to_le_bytes());
		out.extend_from_slice(&node.lookups.to_le_bytes());
		out.extend_from_slice(&node.file_type.to_le_bytes());
		out.extend_from_slice(&comp_count.to_le_bytes());
		for comp in &node.path {
			let len =
				u16::try_from(comp.len()).map_err(|_| invalid("path component exceeds u16"))?;
			out.extend_from_slice(&len.to_le_bytes());
			out.extend_from_slice(comp);
		}
	}

	for handle in &state.handles {
		out.extend_from_slice(&handle.handle.to_le_bytes());
		out.extend_from_slice(&handle.inode.to_le_bytes());
		out.push(u8::from(handle.is_dir));
		out.extend_from_slice(&handle.flags.to_le_bytes());
	}

	Ok(out)
}

pub(crate) fn decode(bytes: &[u8]) -> io::Result<SavedState> {
	let mut cur = Cursor(bytes);
	let magic = cur.take(MAGIC.len())?;
	if magic != MAGIC {
		return Err(invalid("unrecognized passthrough snapshot header"));
	}
	let next_inode = cur.u64()?;
	let next_handle = cur.u64()?;
	let node_count = cur.u32()? as usize;
	let handle_count = cur.u32()? as usize;

	let mut nodes = Vec::with_capacity(node_count.min(4096));
	for _ in 0..node_count {
		let id = cur.u64()?;
		let parent = cur.u64()?;
		let lookups = cur.u64()?;
		let file_type = cur.u32()?;
		let comp_count = cur.u32()? as usize;
		if comp_count == 0 {
			return Err(invalid("saved inode has zero path components"));
		}
		let mut path = Vec::with_capacity(comp_count.min(64));
		for _ in 0..comp_count {
			let len = cur.u16()? as usize;
			if len == 0 {
				return Err(invalid("saved path component is empty"));
			}
			path.push(cur.take(len)?.to_vec());
		}
		nodes.push(SavedNode {
			id,
			parent,
			lookups,
			file_type,
			path,
		});
	}

	let mut handles = Vec::with_capacity(handle_count.min(4096));
	for _ in 0..handle_count {
		let handle = cur.u64()?;
		let inode = cur.u64()?;
		let kind = cur.u8()?;
		let is_dir = match kind {
			0 => false,
			1 => true,
			_ => return Err(invalid("unknown saved handle kind")),
		};
		let flags = cur.u32()?;
		handles.push(SavedHandle {
			handle,
			inode,
			is_dir,
			flags,
		});
	}

	if !cur.0.is_empty() {
		return Err(invalid("trailing bytes in passthrough snapshot state"));
	}

	Ok(SavedState {
		next_inode,
		next_handle,
		nodes,
		handles,
	})
}

fn invalid(msg: &'static str) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, msg)
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
	fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
		if self.0.len() < n {
			return Err(invalid("truncated passthrough snapshot state"));
		}
		let (head, tail) = self.0.split_at(n);
		self.0 = tail;
		Ok(head)
	}

	fn u8(&mut self) -> io::Result<u8> {
		Ok(self.take(1)?[0])
	}

	fn u16(&mut self) -> io::Result<u16> {
		Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
	}

	fn u32(&mut self) -> io::Result<u32> {
		Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
	}

	fn u64(&mut self) -> io::Result<u64> {
		Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
	}
}
