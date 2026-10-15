// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! An index of the files and directories in a cpio archive in the "newc" format, which is the
//! format of the Linux initramfs, as described in the cpio(5) man page.
//!
//! As with the initramfs, the archive may consist of several concatenated archives, which may be
//! separated by zero padding, and entries replace earlier entries with the same path. Entries
//! other than regular files and directories are ignored, as are entries whose paths are not valid
//! UTF-8 or refer to a parent directory. Directories that are missing from the archive are created
//! implicitly.
//!
//! File names are case insensitive, as they are on FAT file systems, but only ASCII characters are
//! folded.

use crate::FileLoader;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

const HEADER_SIZE: usize = 110;
const MAX_NAME_SIZE: usize = 4096;

const S_IFMT: usize = 0o170000;
const S_IFDIR: usize = 0o040000;
const S_IFREG: usize = 0o100000;

/// The index of the root directory in [`Index::nodes`]
pub(crate) const ROOT: usize = 0;

pub(crate) enum NodeKind {
    /// A directory, whose entries are indexed by their upper case names
    Directory(BTreeMap<Vec<u16>, usize>),
    /// A regular file, which consists of `size` bytes at `offset` in the archive
    File { offset: usize, size: usize },
}

pub(crate) struct Node {
    /// The last component of the path of the node, which is empty for the root directory
    pub(crate) name: Vec<u16>,
    /// The index of the parent directory, which is ROOT for the root directory itself
    pub(crate) parent: usize,
    /// The time of the last modification, in seconds since the Unix epoch
    pub(crate) mtime: u32,
    pub(crate) kind: NodeKind,
}

/// The directory tree described by a cpio archive
pub(crate) struct Index {
    pub(crate) nodes: Vec<Node>,
}

/// Returns the upper case form of `name` that it is looked up by
fn upcase(name: &[u16]) -> Vec<u16> {
    name.iter()
        .map(|&c| match u8::try_from(c) {
            Ok(b) => b.to_ascii_uppercase() as u16,
            Err(_) => c,
        })
        .collect()
}

/// Rounds `offset` up to the 4 byte alignment of the headers, names and file contents
fn align4(offset: usize) -> Result<usize, &'static str> {
    offset
        .checked_add(3)
        .map(|o| o & !3)
        .ok_or("truncated cpio archive")
}

/// Fills `buf` with the bytes at `offset` in `archive`
fn read(archive: &dyn FileLoader, offset: usize, buf: &mut [u8]) -> Result<(), &'static str> {
    // SAFETY: `buf` is valid for writes of `buf.len()` bytes.
    unsafe { archive.load_range(buf.as_mut_ptr() as *mut (), offset, buf.len()) }
        .or(Err("failed to read cpio archive"))
}

/// Returns field `n` of the header `hdr`, which consists of 8 hexadecimal digits that follow the
/// magic number and the preceding fields
fn field(hdr: &[u8; HEADER_SIZE], n: usize) -> Result<usize, &'static str> {
    hdr[6 + 8 * n..6 + 8 * (n + 1)].iter().try_fold(0, |v, &d| {
        let d = (d as char).to_digit(16).ok_or("invalid cpio header")?;
        Ok(v << 4 | d as usize)
    })
}

impl Index {
    /// Builds the index of the cpio archive provided by `archive`
    pub(crate) fn new(archive: &dyn FileLoader) -> Result<Self, &'static str> {
        let mut index = Index {
            nodes: vec![Node {
                name: Vec::new(),
                parent: ROOT,
                mtime: 0,
                kind: NodeKind::Directory(BTreeMap::new()),
            }],
        };

        let size = archive.get_size();
        let mut offset = 0;
        while offset < size {
            // Skip the zero padding that may follow the trailer of an archive, which consists of
            // whole 4 byte words, given that the header of the next archive is 4 byte aligned
            let mut word = [0; 4];
            let len = word.len().min(size - offset);
            read(archive, offset, &mut word[..len])?;
            if word[..len].iter().all(|&b| b == 0) {
                offset += len;
                continue;
            }

            let mut hdr = [0; HEADER_SIZE];
            if size - offset < HEADER_SIZE {
                return Err("truncated cpio archive");
            }
            read(archive, offset, &mut hdr)?;
            if &hdr[..6] != b"070701" && &hdr[..6] != b"070702" {
                return Err("invalid cpio header");
            }
            let mode = field(&hdr, 1)?;
            let mtime = field(&hdr, 5)? as u32;
            let file_size = field(&hdr, 6)?;
            let name_size = field(&hdr, 11)?;
            if name_size == 0 || name_size > MAX_NAME_SIZE {
                return Err("invalid cpio header");
            }

            // The NUL terminated name follows the header, and the file contents follow the name,
            // both starting at a 4 byte aligned offset
            let name_offset = offset + HEADER_SIZE;
            let data_offset = align4(name_offset.saturating_add(name_size))?;
            let data_end = data_offset
                .checked_add(file_size)
                .filter(|&end| end <= size)
                .ok_or("truncated cpio archive")?;

            let mut name = vec![0; name_size];
            read(archive, name_offset, &mut name)?;
            let Some(len) = name.iter().position(|&b| b == 0) else {
                return Err("invalid cpio header");
            };
            name.truncate(len);

            if name != b"TRAILER!!!" {
                match mode & S_IFMT {
                    S_IFDIR => index.insert(&name, mtime, None),
                    S_IFREG => index.insert(&name, mtime, Some((data_offset, file_size))),
                    _ => {}
                }
            }
            offset = align4(data_end)?;
        }
        Ok(index)
    }

    /// Returns the entry `name` of directory `dir`, which is created as an empty directory if it
    /// does not exist. If `dir` is a file, it is replaced by an empty directory first.
    fn entry(&mut self, dir: usize, name: &str) -> usize {
        let name: Vec<u16> = name.encode_utf16().collect();
        let key = upcase(&name);
        let new = self.nodes.len();
        let node = &mut self.nodes[dir];
        if let NodeKind::File { .. } = node.kind {
            node.kind = NodeKind::Directory(BTreeMap::new());
        }
        let NodeKind::Directory(entries) = &mut node.kind else {
            return dir;
        };
        if let Some(&n) = entries.get(&key) {
            return n;
        }
        entries.insert(key, new);
        self.nodes.push(Node {
            name,
            parent: dir,
            mtime: 0,
            kind: NodeKind::Directory(BTreeMap::new()),
        });
        new
    }

    /// Records the archive entry `path`, which is a regular file with contents at the given offset
    /// and of the given size in the archive if `file` is not None, or a directory otherwise.
    fn insert(&mut self, path: &[u8], mtime: u32, file: Option<(usize, usize)>) {
        let Ok(path) = core::str::from_utf8(path) else {
            return;
        };
        let components: Vec<&str> = path
            .split('/')
            .filter(|&c| !c.is_empty() && c != ".")
            .collect();
        if components.contains(&"..") {
            return;
        }
        // An entry for the root directory itself carries no information
        let Some((last, dirs)) = components.split_last() else {
            return;
        };

        let dir = dirs.iter().fold(ROOT, |dir, c| self.entry(dir, c));
        let n = self.entry(dir, last);
        let node = &mut self.nodes[n];
        node.mtime = mtime;
        match file {
            Some((offset, size)) => node.kind = NodeKind::File { offset, size },
            None => {
                if let NodeKind::File { .. } = node.kind {
                    node.kind = NodeKind::Directory(BTreeMap::new());
                }
            }
        }
    }

    /// Returns the node that `path` refers to, which is a backslash separated path relative to node
    /// `start`, or to the root directory if it starts with a backslash. The path may contain "."
    /// and ".." components, but the latter may not refer to the parent of the root directory.
    pub(crate) fn lookup(&self, start: usize, path: &[u16]) -> Option<usize> {
        const BACKSLASH: u16 = b'\\' as u16;
        const DOT: u16 = b'.' as u16;

        let mut node = if path.first() == Some(&BACKSLASH) {
            ROOT
        } else {
            start
        };
        for component in path.split(|&c| c == BACKSLASH) {
            match component {
                [] | [DOT] => {}
                [DOT, DOT] if node == ROOT => return None,
                [DOT, DOT] => node = self.nodes[node].parent,
                name => {
                    let NodeKind::Directory(entries) = &self.nodes[node].kind else {
                        return None;
                    };
                    node = *entries.get(&upcase(name))?;
                }
            }
        }
        Some(node)
    }
}
