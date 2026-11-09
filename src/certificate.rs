//! Evidence-range certificate: not a full-content snapshot and not a gameplay guarantee.
use crate::{Entry, Profile, SourceTree};
use std::collections::BTreeSet;
use std::io;
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
/// Incremental SHA-256 for analysis evidence and optional full-content hashing.
pub struct Sha256 {
    h: [u32; 8],
    block: [u8; 64],
    used: usize,
    len: u64,
}
impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}
impl Sha256 {
    pub fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            used: 0,
            len: 0,
        }
    }
    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, b) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(b.try_into().unwrap())
        }
        for i in 16..64 {
            let a = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let b = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(a)
                .wrapping_add(w[i - 7])
                .wrapping_add(b)
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut z] = self.h;
        for i in 0..64 {
            let s = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t = z
                .wrapping_add(s)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let q = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            z = g;
            g = f;
            f = e;
            e = d.wrapping_add(t);
            d = c;
            c = b;
            b = a;
            a = t.wrapping_add(q)
        }
        for (x, y) in self.h.iter_mut().zip([a, b, c, d, e, f, g, z]) {
            *x = x.wrapping_add(y)
        }
    }
    pub fn update(&mut self, mut input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u64);
        if self.used > 0 {
            let n = (64 - self.used).min(input.len());
            self.block[self.used..self.used + n].copy_from_slice(&input[..n]);
            self.used += n;
            input = &input[n..];
            if self.used == 64 {
                let block = self.block;
                self.compress(&block);
                self.used = 0
            } else {
                return;
            }
        }
        while input.len() >= 64 {
            let block = <&[u8; 64]>::try_from(&input[..64]).unwrap();
            self.compress(block);
            input = &input[64..]
        }
        self.block[..input.len()].copy_from_slice(input);
        self.used = input.len()
    }
    pub fn finalize(mut self) -> [u8; 32] {
        let bits = self.len.wrapping_mul(8);
        self.block[self.used] = 0x80;
        self.used += 1;
        if self.used > 56 {
            self.block[self.used..].fill(0);
            let block = self.block;
            self.compress(&block);
            self.block = [0; 64];
        } else {
            self.block[self.used..56].fill(0)
        }
        self.block[56..].copy_from_slice(&bits.to_be_bytes());
        let block = self.block;
        self.compress(&block);
        let mut out = [0; 32];
        for (chunk, x) in out.chunks_exact_mut(4).zip(self.h) {
            chunk.copy_from_slice(&x.to_be_bytes())
        }
        out
    }
}
pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}
pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut out, x| {
            write!(out, "{x:02x}").unwrap();
            out
        })
}
fn unhex(s: &str) -> io::Result<Vec<u8>> {
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(invalid("bad hex"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| invalid("bad hex")))
        .collect()
}
fn hash(s: &str) -> io::Result<[u8; 32]> {
    unhex(s)?.try_into().map_err(|_| invalid("bad hash"))
}
fn field(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u64).to_be_bytes());
    buf.extend_from_slice(b)
}
fn inventory(files: &[Entry]) -> io::Result<[u8; 32]> {
    let mut files = files.to_vec();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    if files.windows(2).any(|w| w[0].path == w[1].path) {
        return Err(invalid("duplicate inventory"));
    }
    let mut b = Vec::new();
    for f in files {
        field(&mut b, f.path.as_bytes());
        b.extend_from_slice(&f.size.to_be_bytes())
    }
    Ok(digest(&b))
}
fn selection(s: &BTreeSet<String>) -> [u8; 32] {
    let mut b = Vec::new();
    for p in s {
        field(&mut b, p.as_bytes())
    }
    digest(&b)
}
fn profile(p: &Profile) -> [u8; 32] {
    let mut b = Vec::new();
    field(&mut b, p.toml.as_bytes());
    for (n, v) in &p.lists {
        field(&mut b, n.as_bytes());
        field(&mut b, v.as_bytes())
    }
    digest(&b)
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceRange {
    pub path: String,
    pub offset: u64,
    pub len: u64,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    analyzer: &'static str,
    inventory: [u8; 32],
    selection: [u8; 32],
    profile: [u8; 32],
    pub ranges: Vec<EvidenceRange>,
}
/// Records the explicit ranges observed by the caller. Empty ranges are rejected.
pub fn create(
    files: &[Entry],
    selected: &BTreeSet<String>,
    p: &Profile,
    ranges: &[EvidenceRange],
) -> io::Result<Certificate> {
    crate::forge::verify_generated(p, files, selected)?;
    let sizes: std::collections::HashMap<&str, u64> =
        files.iter().map(|f| (f.path.as_str(), f.size)).collect();
    let mut r = ranges.to_vec();
    r.sort();
    r.dedup();
    if r.windows(2)
        .any(|w| w[0].path == w[1].path && w[0].offset == w[1].offset && w[0].len == w[1].len)
    {
        return Err(invalid("contradictory evidence hashes for the same range"));
    }
    if r.is_empty() {
        return Err(invalid("missing evidence ranges"));
    }
    for x in &r {
        let size = *sizes
            .get(x.path.as_str())
            .ok_or_else(|| invalid("range outside inventory"))?;
        if x.len == 0 || x.offset.checked_add(x.len).is_none_or(|end| end > size) {
            return Err(invalid("invalid evidence range"));
        }
    }
    Ok(Certificate {
        analyzer: env!("CARGO_PKG_VERSION"),
        inventory: inventory(files)?,
        selection: selection(selected),
        profile: profile(p),
        ranges: r,
    })
}
impl Certificate {
    /// Deterministic text encoding. Versions are bound in the header.
    pub fn serialize(&self) -> String {
        let mut s=format!("ps5-pack-certificate-v1\nanalyzer={}\npolicy=offline-conservative-v1\nforge=0.5.4\nruntime=0.3.2\ncoverage=evidence-ranges-only\ninventory={}\nselection={}\nprofile={}\n",self.analyzer,hex(&self.inventory),hex(&self.selection),hex(&self.profile));
        for r in &self.ranges {
            s.push_str(&format!(
                "range={} {} {} {}\n",
                hex(r.path.as_bytes()),
                r.offset,
                r.len,
                hex(&r.sha256)
            ))
        }
        s
    }
    pub fn parse(s: &str) -> io::Result<Self> {
        if s.len() > 128 * 1024 * 1024 {
            return Err(invalid("certificate exceeds 128 MiB"));
        }
        let mut l = s.lines();
        if l.next() != Some("ps5-pack-certificate-v1") {
            return Err(invalid("unsupported certificate"));
        }
        let analyzer = match l.next() {
            Some("analyzer=0.3.0") => "0.3.0",
            Some(concat!("analyzer=", env!("CARGO_PKG_VERSION"))) => env!("CARGO_PKG_VERSION"),
            _ => return Err(invalid("unsupported analyzer version")),
        };
        for expect in [
            "policy=offline-conservative-v1",
            "forge=0.5.4",
            "runtime=0.3.2",
            "coverage=evidence-ranges-only",
        ] {
            if l.next() != Some(expect) {
                return Err(invalid("unsupported certificate"));
            }
        }
        let take = |l: &mut std::str::Lines<'_>, prefix: &str| -> io::Result<[u8; 32]> {
            hash(
                l.next()
                    .and_then(|s| s.strip_prefix(prefix))
                    .ok_or_else(|| invalid("missing hash"))?,
            )
        };
        let inventory = take(&mut l, "inventory=")?;
        let selection = take(&mut l, "selection=")?;
        let profile = take(&mut l, "profile=")?;
        let mut ranges = Vec::new();
        for line in l {
            if ranges.len() >= 2_000_000 || line.len() > 131_200 {
                return Err(invalid("certificate range limit exceeded"));
            }
            let mut p = line
                .strip_prefix("range=")
                .ok_or_else(|| invalid("bad range"))?
                .split(' ');
            let path = String::from_utf8(unhex(p.next().ok_or_else(|| invalid("bad range"))?)?)
                .map_err(|_| invalid("bad path"))?;
            let offset: u64 = p
                .next()
                .ok_or_else(|| invalid("bad range"))?
                .parse()
                .map_err(|_| invalid("bad offset"))?;
            let len: u64 = p
                .next()
                .ok_or_else(|| invalid("bad range"))?
                .parse()
                .map_err(|_| invalid("bad length"))?;
            if path.is_empty()
                || path.len() > 65_535
                || path.contains(['\\', ':'])
                || path.chars().any(char::is_control)
                || path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || len == 0
                || offset.checked_add(len).is_none()
            {
                return Err(invalid("invalid evidence range"));
            }
            let sha256 = hash(p.next().ok_or_else(|| invalid("bad range"))?)?;
            if p.next().is_some() {
                return Err(invalid("bad range"));
            }
            ranges.push(EvidenceRange {
                path,
                offset,
                len,
                sha256,
            })
        }
        if ranges.is_empty()
            || ranges.windows(2).any(|w| {
                w[0] >= w[1]
                    || (w[0].path == w[1].path
                        && w[0].offset == w[1].offset
                        && w[0].len == w[1].len)
            })
        {
            return Err(invalid("bad range order"));
        }
        Ok(Self {
            analyzer,
            inventory,
            selection,
            profile,
            ranges,
        })
    }
    pub fn verify(
        &self,
        tree: &mut (impl SourceTree + ?Sized),
        selected: &BTreeSet<String>,
        p: &Profile,
    ) -> io::Result<()> {
        if self.ranges.is_empty() {
            return Err(invalid("missing evidence ranges"));
        }
        let files = tree.files().to_vec();
        crate::forge::verify_generated(p, &files, selected)?;
        if inventory(&files)? != self.inventory
            || selection(selected) != self.selection
            || profile(p) != self.profile
        {
            return Err(invalid("certificate binding mismatch"));
        }
        let sizes: std::collections::HashMap<&str, u64> =
            files.iter().map(|f| (f.path.as_str(), f.size)).collect();
        for r in &self.ranges {
            let size = *sizes
                .get(r.path.as_str())
                .ok_or_else(|| invalid("range outside inventory"))?;
            if r.len == 0 || r.offset.checked_add(r.len).is_none_or(|x| x > size) {
                return Err(invalid("invalid range"));
            }
            let mut h = Sha256::new();
            let mut done = 0u64;
            while done < r.len {
                let n = (r.len - done).min(4 * 1024 * 1024) as usize;
                let offset = r.offset + done;
                let b = tree.read_range(&r.path, offset, n).map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("evidence read {} at offset {offset}: {e}", r.path),
                    )
                })?;
                if b.len() != n {
                    return Err(invalid(&format!(
                        "short evidence read {} at offset {offset}",
                        r.path
                    )));
                }
                h.update(&b);
                done += n as u64;
            }
            if h.finalize() != r.sha256 {
                return Err(invalid(&format!(
                    "evidence changed {} at range offset {}",
                    r.path, r.offset
                )));
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct ChunkTree {
        files: Vec<Entry>,
        data: Vec<u8>,
    }
    impl SourceTree for ChunkTree {
        fn files(&self) -> &[Entry] {
            &self.files
        }
        fn read_range(&mut self, _: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
            if len > 4 * 1024 * 1024 {
                return Err(invalid("oversized read"));
            }
            let start = offset as usize;
            Ok(self.data[start..start + len].to_vec())
        }
    }
    #[test]
    fn verifies_large_range_in_chunks_and_detects_corruption() {
        let data = vec![42; 4 * 1024 * 1024 + 17];
        let files = vec![Entry {
            path: "data/a.bin".into(),
            size: data.len() as u64,
        }];
        let selected = BTreeSet::new();
        let p = Profile {
            toml: "[pack]\ndefault_action = \"loose\"\n".into(),
            lists: Default::default(),
        };
        let range = EvidenceRange {
            path: files[0].path.clone(),
            offset: 0,
            len: data.len() as u64,
            sha256: digest(&data),
        };
        let cert = create(&files, &selected, &p, std::slice::from_ref(&range)).unwrap();
        let mut tree = ChunkTree { files, data };
        cert.verify(&mut tree, &selected, &p).unwrap();
        let mut without_evidence = cert.clone();
        without_evidence.ranges.clear();
        assert!(without_evidence.verify(&mut tree, &selected, &p).is_err());
        tree.data[4 * 1024 * 1024 + 3] ^= 1;
        let err = cert
            .verify(&mut tree, &selected, &p)
            .unwrap_err()
            .to_string();
        assert!(err.contains("data/a.bin") && err.contains("offset 0"));
        let mut conflicting = range.clone();
        conflicting.sha256[0] ^= 1;
        assert!(create(&tree.files, &selected, &p, &[range, conflicting]).is_err());
    }
    #[test]
    fn sha_vectors() {
        assert_eq!(
            hex(&digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let data = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&digest(&data)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        for chunk in [1, 3, 55, 56, 63, 64, 65, 127, 1024] {
            let mut h = Sha256::new();
            for part in data.chunks(chunk) {
                h.update(part)
            }
            assert_eq!(h.finalize(), digest(&data));
        }
    }
}
