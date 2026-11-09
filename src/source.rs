use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub size: u64,
}

/// A logical PS5 dump with normalized, case-preserving relative paths.
///
/// The adapter must return exactly `len` bytes or an error and present an
/// immutable view for the duration of one analysis.
pub trait SourceTree {
    fn files(&self) -> &[Entry];
    fn read_range(&mut self, path: &str, offset: u64, len: usize) -> io::Result<Vec<u8>>;

    /// Read prefixes in the order of `entries`. Folder adapters may overlap reads.
    fn read_headers(&mut self, entries: &[Entry], len: usize) -> io::Result<Vec<Vec<u8>>> {
        entries
            .iter()
            .map(|entry| self.read_range(&entry.path, 0, entry.size.min(len as u64) as usize))
            .collect()
    }
}

pub struct FolderSource {
    root: PathBuf,
    files: Vec<Entry>,
    stamps: BTreeMap<String, Stamp>,
}

// Metadata is a change detector, not a filesystem snapshot: timestamps can be
// restored and a path can change between checks. Callers must still keep the
// dump immutable while analyzing it.
#[derive(PartialEq, Eq)]
struct Stamp {
    size: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
}

impl Stamp {
    fn from_metadata(meta: &fs::Metadata) -> Self {
        Self {
            size: meta.len(),
            modified: meta.modified().ok(),
            created: meta.created().ok(),
        }
    }
}

impl FolderSource {
    pub fn open(root: &Path) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() || is_link(&metadata) {
            return Err(invalid("the input must be a real directory"));
        }
        let root = root.canonicalize()?;
        let mut files = Vec::new();
        let mut stamps = BTreeMap::new();
        let mut dirs = vec![(root.clone(), String::new())];
        while let Some((dir, prefix)) = dirs.pop() {
            for child in fs::read_dir(dir)? {
                let child = child?;
                let name = child
                    .file_name()
                    .into_string()
                    .map_err(|_| invalid("non-UTF-8 path in dump"))?;
                let path = format!("{prefix}{name}");
                let meta = fs::symlink_metadata(child.path())?;
                if is_link(&meta) {
                    return Err(invalid(format!("link or reparse point in dump: {path}")));
                }
                if meta.is_dir() {
                    dirs.push((child.path(), format!("{path}/")));
                } else if meta.is_file() {
                    stamps.insert(path.clone(), Stamp::from_metadata(&meta));
                    files.push(Entry {
                        path,
                        size: meta.len(),
                    });
                } else {
                    return Err(invalid(format!("unsupported entry: {path}")));
                }
            }
        }
        files.sort_unstable_by(|a, b| a.path.cmp(&b.path));
        Ok(Self {
            root,
            files,
            stamps,
        })
    }

    fn entry(&self, path: &str) -> io::Result<&Entry> {
        self.files
            .binary_search_by(|entry| entry.path.as_str().cmp(path))
            .map(|index| &self.files[index])
            .map_err(|_| invalid(format!("unlisted file: {path}")))
    }
}

impl SourceTree for FolderSource {
    fn files(&self) -> &[Entry] {
        &self.files
    }

    fn read_range(&mut self, path: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        read_file(
            &self.root,
            self.entry(path)?,
            &self.stamps[path],
            offset,
            len,
        )
    }

    fn read_headers(&mut self, entries: &[Entry], len: usize) -> io::Result<Vec<Vec<u8>>> {
        // A preflight batch bounds the buffers and joins in input order,
        // independently of the number of available threads.
        let workers = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(8);
        let chunk_size = entries.len().div_ceil(workers).max(1);
        let source = &*self;
        std::thread::scope(|scope| {
            let mut jobs = Vec::new();
            for chunk in entries.chunks(chunk_size) {
                jobs.push(scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|entry| {
                            let actual = source.entry(&entry.path)?;
                            if actual.size != entry.size {
                                return Err(invalid(format!(
                                    "entry size differs from inventory: {}",
                                    entry.path
                                )));
                            }
                            read_file(
                                &source.root,
                                actual,
                                &source.stamps[&entry.path],
                                0,
                                actual.size.min(len as u64) as usize,
                            )
                        })
                        .collect::<io::Result<Vec<_>>>()
                }));
            }
            let mut result = Vec::with_capacity(entries.len());
            for job in jobs {
                result.extend(job.join().map_err(|_| invalid("header reader failed"))??);
            }
            Ok(result)
        })
    }
}

fn read_file(
    root: &Path,
    entry: &Entry,
    stamp: &Stamp,
    offset: u64,
    len: usize,
) -> io::Result<Vec<u8>> {
    if offset
        .checked_add(len as u64)
        .is_none_or(|end| end > entry.size)
    {
        return Err(invalid(format!("out-of-range read: {}", entry.path)));
    }
    let mut path = root.to_path_buf();
    for component in entry.path.split('/') {
        path.push(component);
        if is_link(&fs::symlink_metadata(&path)?) {
            return Err(invalid(format!(
                "link or reparse point in dump: {}",
                entry.path
            )));
        }
    }
    let mut file = File::open(path)?;
    if Stamp::from_metadata(&file.metadata()?) != *stamp {
        return Err(invalid(format!(
            "file metadata changed during analysis: {}",
            entry.path
        )));
    }
    if offset != 0 {
        file.seek(SeekFrom::Start(offset))?;
    }
    let mut bytes = vec![0; len];
    file.read_exact(&mut bytes)?;
    if Stamp::from_metadata(&file.metadata()?) != *stamp {
        return Err(invalid(format!(
            "file metadata changed during analysis: {}",
            entry.path
        )));
    }
    Ok(bytes)
}

fn is_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn detects_same_size_change_when_modification_time_changes() {
        let root = std::env::temp_dir().join(format!(
            "ps5-analyzer-source-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("payload");
        fs::write(&path, b"old").unwrap();
        let file = File::options().write(true).open(&path).unwrap();
        file.set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(10)))
            .unwrap();
        let mut source = FolderSource::open(&root).unwrap();
        fs::write(&path, b"new").unwrap();
        file.set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(20)))
            .unwrap();
        assert!(source.read_range("payload", 0, 3).is_err());
        drop(file);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_directory_in_inventory() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!(
            "ps5-analyzer-link-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir(&root).unwrap();
        symlink(&root, root.join("link")).unwrap();
        assert!(FolderSource::open(&root).is_err());
        fs::remove_file(root.join("link")).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
