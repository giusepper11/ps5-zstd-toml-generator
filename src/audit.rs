//! Bounded, read-only evidence collection over a Forge/folder SourceTree.
use crate::{
    certificate::{digest, EvidenceRange},
    Entry, SourceTree,
};
use std::collections::BTreeMap;
use std::io;

pub struct AuditedSource<T> {
    inner: T,
    ranges: BTreeMap<(String, u64, u64), [u8; 32]>,
    pub bytes_read: u64,
    poisoned: bool,
}

impl<T: SourceTree> AuditedSource<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            ranges: BTreeMap::new(),
            bytes_read: 0,
            poisoned: false,
        }
    }
    pub fn ranges(&self) -> io::Result<Vec<EvidenceRange>> {
        if self.poisoned {
            return Err(io::Error::other(
                "source had an inconsistent or failed evidence read",
            ));
        }
        Ok(self
            .ranges
            .iter()
            .map(|((path, offset, len), sha256)| EvidenceRange {
                path: path.clone(),
                offset: *offset,
                len: *len,
                sha256: *sha256,
            })
            .collect())
    }
    fn record(&mut self, path: &str, offset: u64, data: &[u8], expected: usize) -> io::Result<()> {
        if data.len() != expected {
            self.poisoned = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short evidence read",
            ));
        }
        self.bytes_read = self
            .bytes_read
            .checked_add(data.len() as u64)
            .ok_or_else(|| io::Error::other("read counter overflow"))?;
        if data.is_empty() {
            return Ok(());
        }
        let hash = digest(data);
        // When a new read contains a previously hashed range (e.g. an ELF
        // header followed by the complete image), compare that overlap too.
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| io::Error::other("range overflow"))?;
        for ((_, old_offset, old_len), old_hash) in self
            .ranges
            .range((path.to_owned(), 0, 0)..=(path.to_owned(), u64::MAX, u64::MAX))
        {
            if *old_offset >= offset
                && old_offset
                    .checked_add(*old_len)
                    .is_some_and(|old_end| old_end <= end)
            {
                let begin = (*old_offset - offset) as usize;
                if digest(&data[begin..begin + *old_len as usize]) != *old_hash {
                    self.poisoned = true;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "overlapping evidence changed during analysis",
                    ));
                }
            }
        }
        if let Some(old) = self
            .ranges
            .get(&(path.to_owned(), offset, data.len() as u64))
        {
            if *old != hash {
                self.poisoned = true;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "evidence changed during analysis",
                ));
            }
        }
        self.ranges
            .insert((path.to_owned(), offset, data.len() as u64), hash);
        Ok(())
    }
    /// Optional complete byte coverage. Streams 4 MiB at a time, never copies
    /// assets to disk. Potentially expensive I/O: caller must opt in.
    pub fn hash_all(&mut self, mut progress: impl FnMut(usize, usize)) -> io::Result<()> {
        let files = self.files().to_vec();
        for (i, file) in files.iter().enumerate() {
            let mut offset = 0;
            while offset < file.size {
                let len = (file.size - offset).min(4 * 1024 * 1024) as usize;
                self.read_range(&file.path, offset, len)?;
                offset += len as u64;
            }
            progress(i + 1, files.len());
        }
        Ok(())
    }
}

impl<T: SourceTree> SourceTree for AuditedSource<T> {
    fn files(&self) -> &[Entry] {
        self.inner.files()
    }
    fn read_range(&mut self, path: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let data = self
            .inner
            .read_range(path, offset, len)
            .inspect_err(|_| self.poisoned = true)?;
        self.record(path, offset, &data, len)?;
        Ok(data)
    }
    fn read_headers(&mut self, entries: &[Entry], len: usize) -> io::Result<Vec<Vec<u8>>> {
        let data = self
            .inner
            .read_headers(entries, len)
            .inspect_err(|_| self.poisoned = true)?;
        if data.len() != entries.len() {
            self.poisoned = true;
            return Err(io::Error::other("wrong header batch count"));
        }
        for (f, bytes) in entries.iter().zip(&data) {
            self.record(&f.path, 0, bytes, f.size.min(len as u64) as usize)?;
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Changing {
        files: Vec<Entry>,
        value: u8,
    }
    impl SourceTree for Changing {
        fn files(&self) -> &[Entry] {
            &self.files
        }
        fn read_range(&mut self, _: &str, _: u64, len: usize) -> io::Result<Vec<u8>> {
            self.value += 1;
            Ok(vec![self.value; len])
        }
    }
    #[test]
    fn detects_same_size_changed_evidence() {
        let mut source = AuditedSource::new(Changing {
            files: vec![Entry {
                path: "a".into(),
                size: 4,
            }],
            value: 0,
        });
        source.read_range("a", 0, 4).unwrap();
        assert!(source.read_range("a", 0, 4).is_err());
        assert!(source.ranges().is_err());
    }
}
