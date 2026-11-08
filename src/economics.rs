//! Deterministic, sampled block economics. Results describe the observed samples only.
//! The caller supplies already selected entries in a single meaningful stratum (for example,
//! asset kind, extension and subtree); grouping and safety eligibility are not inferred here.
use crate::{Entry, SourceTree};
use std::io;
const BLOCK: u64 = 256 * 1024;
const FILES: usize = 16;
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
/// A caller-supplied encoder. Its claimed identity is not verified by this module.
pub trait Compressor {
    fn identity(&self) -> &str;
    fn compressed_len(&mut self, block: &[u8]) -> io::Result<u64>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    pub path: String,
    pub offset: u64,
    pub raw: u64,
    pub encoded: u64,
    pub stored: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Economics {
    pub compressor_claim_unverified: String,
    pub files_in_stratum: usize,
    pub sampled_files: usize,
    pub samples: Vec<Sample>,
    pub raw_sample_bytes: u64,
    pub stored_sample_bytes: u64,
    /// Model: 32 bytes per selected file, 8 per logical 256 KiB block, plus UTF-8 path bytes.
    /// A sizing assumption, not a measured Forge index size.
    pub model_index_bytes: u64,
    /// Allocation unit supplied by caller; 1 means no allocation rounding.
    pub allocation_unit: u64,
    /// Separately allocated sample blocks rounded up to the given unit, before and after coding.
    /// This is a sample-only scenario, not a prediction of the actual pack's allocation.
    pub sample_allocated_raw: u64,
    pub sample_allocated_stored: u64,
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("economics size overflow"))
}
fn round(n: u64, unit: u64) -> io::Result<u64> {
    if n == 0 {
        return Ok(0);
    }
    let units = (n - 1) / unit + 1;
    units
        .checked_mul(unit)
        .ok_or_else(|| invalid("allocation overflow"))
}
/// Sample at most 16 files in deterministic size/path order. Each file contributes its first,
/// middle and last distinct aligned blocks. `allocation_unit` must be nonzero.
/// `stored` models Forge's raw fallback when the encoded frame does not shrink a block.
pub fn measure(
    tree: &mut (impl SourceTree + ?Sized),
    entries: &[Entry],
    encoder: &mut impl Compressor,
    allocation_unit: u64,
) -> io::Result<Economics> {
    if allocation_unit == 0 {
        return Err(invalid("zero allocation unit"));
    }
    let identity = encoder.identity().to_owned();
    if identity.trim().is_empty() {
        return Err(invalid("missing compressor identity"));
    }
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| (a.size, &a.path).cmp(&(b.size, &b.path)));
    let mut names = std::collections::BTreeSet::new();
    let mut index = 0u64;
    for e in &sorted {
        if !names.insert(&e.path) {
            return Err(invalid("duplicate entry"));
        }
        let chunks = e.size / BLOCK + u64::from(e.size % BLOCK != 0);
        index = add(
            index,
            add(
                add(
                    32,
                    u64::try_from(e.path.len()).map_err(|_| invalid("path too long"))?,
                )?,
                chunks
                    .checked_mul(8)
                    .ok_or_else(|| invalid("index overflow"))?,
            )?,
        )?
    }
    let eligible: Vec<&Entry> = sorted.iter().filter(|e| e.size > 0).collect();
    let count = eligible.len().min(FILES);
    let mut out = Economics {
        compressor_claim_unverified: identity,
        files_in_stratum: entries.len(),
        sampled_files: count,
        samples: Vec::new(),
        raw_sample_bytes: 0,
        stored_sample_bytes: 0,
        model_index_bytes: index,
        allocation_unit,
        sample_allocated_raw: 0,
        sample_allocated_stored: 0,
    };
    for i in 0..count {
        let e = eligible[i * (eligible.len() - 1) / (count - 1).max(1)];
        let blocks = e.size / BLOCK + u64::from(e.size % BLOCK != 0);
        let indexes = std::collections::BTreeSet::from([0, (blocks - 1) / 2, blocks - 1]);
        for n in indexes {
            let offset = n * BLOCK;
            let len = (e.size - offset).min(BLOCK);
            let data = tree.read_range(&e.path, offset, len as usize)?;
            if data.len() as u64 != len {
                return Err(invalid("short sample read"));
            }
            let encoded = encoder.compressed_len(&data)?;
            let stored = encoded.min(len);
            out.raw_sample_bytes = add(out.raw_sample_bytes, len)?;
            out.stored_sample_bytes = add(out.stored_sample_bytes, stored)?;
            out.sample_allocated_raw = add(out.sample_allocated_raw, round(len, allocation_unit)?)?;
            out.sample_allocated_stored =
                add(out.sample_allocated_stored, round(stored, allocation_unit)?)?;
            out.samples.push(Sample {
                path: e.path.clone(),
                offset,
                raw: len,
                encoded,
                stored,
            });
        }
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Tree {
        files: Vec<Entry>,
        short: bool,
    }
    impl SourceTree for Tree {
        fn files(&self) -> &[Entry] {
            &self.files
        }
        fn read_range(&mut self, _: &str, _: u64, n: usize) -> io::Result<Vec<u8>> {
            Ok(vec![0; if self.short { n.saturating_sub(1) } else { n }])
        }
    }
    struct Ratio(bool);
    impl Compressor for Ratio {
        fn identity(&self) -> &str {
            "test identity"
        }
        fn compressed_len(&mut self, b: &[u8]) -> io::Result<u64> {
            Ok(if self.0 {
                b.len() as u64 + 1
            } else {
                b.len() as u64 / 2
            })
        }
    }
    fn e(p: &str, n: u64) -> Entry {
        Entry {
            path: p.into(),
            size: n,
        }
    }
    #[test]
    fn tiny_empty_fallback_and_allocation() {
        let entries = vec![e("empty", 0), e("tiny", 7)];
        let mut t = Tree {
            files: entries.clone(),
            short: false,
        };
        let r = measure(&mut t, &entries, &mut Ratio(true), 4096).unwrap();
        assert_eq!(r.sampled_files, 1);
        assert_eq!(r.samples.len(), 1);
        assert_eq!((r.raw_sample_bytes, r.stored_sample_bytes), (7, 7));
        assert_eq!(
            (r.sample_allocated_raw, r.sample_allocated_stored),
            (4096, 4096)
        );
        assert_eq!(r.model_index_bytes, 32 * 2 + 5 + 4 + 8);
    }
    #[test]
    fn windows_are_aligned_distinct_and_weighted() {
        let entries = vec![e("a", BLOCK * 2 + 1), e("b", 1)];
        let mut t = Tree {
            files: entries.clone(),
            short: false,
        };
        let r = measure(&mut t, &entries, &mut Ratio(false), 1).unwrap();
        assert_eq!(
            r.samples
                .iter()
                .filter(|s| s.path == "a")
                .map(|s| s.offset)
                .collect::<Vec<_>>(),
            vec![0, BLOCK, 2 * BLOCK]
        );
        assert_eq!(r.samples.len(), 4);
        assert_eq!(r.raw_sample_bytes, 2 * BLOCK + 2);
        assert_eq!(r.stored_sample_bytes, BLOCK);
    }
    #[test]
    fn rejects_bad_input_and_short_read() {
        let entries = vec![e("a", 10)];
        let mut t = Tree {
            files: entries.clone(),
            short: true,
        };
        assert!(measure(&mut t, &entries, &mut Ratio(true), 1).is_err());
        assert!(measure(&mut t, &entries, &mut Ratio(true), 0).is_err());
        assert!(measure(&mut t, &[e("a", 1), e("a", 2)], &mut Ratio(true), 1).is_err());
    }
    #[test]
    fn caps_files_and_is_order_independent() {
        let entries: Vec<_> = (0..40).map(|i| e(&format!("f{i:02}"), i + 1)).collect();
        let mut t = Tree {
            files: entries.clone(),
            short: false,
        };
        let a = measure(&mut t, &entries, &mut Ratio(false), 1).unwrap();
        let b = measure(
            &mut t,
            &entries.iter().cloned().rev().collect::<Vec<_>>(),
            &mut Ratio(false),
            1,
        )
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.sampled_files, 16);
    }
}
