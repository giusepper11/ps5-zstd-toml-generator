use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io;

use ruzstd::encoding::{compress_to_vec, CompressionLevel};

use crate::assets::{AssetKind, PayloadKind};
use crate::{source::invalid, Entry, Evidence, SourceTree};

const MIN_FILE_BYTES: u64 = 2 * 1024;
const SAMPLE_BYTES: u64 = 64 * 1024;
const FILES_PER_FAMILY: usize = 16;
const MAX_CAS_SAMPLES: usize = 256;
const MIN_SAVINGS: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Access {
    AprArgument,
    AprScope,
    Catalogue,
    FrostbiteCas,
}

pub(crate) struct Findings<'a> {
    pub apr: bool,
    pub incomplete: bool,
    pub aio: bool,
    pub directory_scopes: &'a BTreeSet<String>,
    pub direct: &'a BTreeSet<&'a str>,
    pub catalogue: &'a BTreeSet<&'a str>,
    pub apr_scopes: &'a BTreeSet<String>,
    pub keep: &'a BTreeSet<&'a str>,
    pub blocked_scopes: &'a BTreeSet<String>,
    pub frostbite_cas_candidates: bool,
}

#[derive(Default)]
pub(crate) struct PolicyResult {
    pub selected: BTreeMap<String, Evidence>,
    pub selected_bytes: u64,
    families: Vec<Family>,
    cas: CasSurvey,
    loose: BTreeMap<&'static str, (usize, u64)>,
    pub reasons: BTreeMap<String, &'static str>,
}

#[derive(Default)]
struct CasSurvey {
    files: usize,
    bytes: u64,
    samples: usize,
    sampled_bytes: u64,
    stored_bytes: u64,
    favorable: usize,
}

struct Family {
    extension: String,
    kind: Option<PayloadKind>,
    files: usize,
    bytes: u64,
    samples: usize,
    sampled_bytes: u64,
    stored_bytes: u64,
    compress: bool,
}

struct Candidate<'a> {
    entry: &'a Entry,
    access: Access,
}

pub(crate) fn select(
    tree: &mut (impl SourceTree + ?Sized),
    files: &[Entry],
    kinds: &[AssetKind],
    findings: Findings<'_>,
    choose_frostbite_cas: impl FnOnce(usize) -> io::Result<bool>,
) -> io::Result<PolicyResult> {
    let mut result = PolicyResult::default();
    let mut groups = BTreeMap::<(Option<PayloadKind>, &str, String), Vec<Candidate<'_>>>::new();
    let mut cas = Vec::new();
    for (entry, &kind) in files.iter().zip(kinds) {
        if kind == AssetKind::FrostbiteCas {
            result.cas.files += 1;
            result.cas.bytes += entry.size;
            if let Some(reason) = exclusion(entry, kind, &findings) {
                result.leave(entry, reason);
            } else {
                cas.push(entry);
            }
            continue;
        }
        let (asset, access) = match eligibility(entry, kind, &findings) {
            Ok(eligible) => eligible,
            Err(reason) => {
                result.leave(entry, reason);
                continue;
            }
        };
        let extension = extension(&entry.path);
        groups
            .entry((asset, extension, stratum(&entry.path)))
            .or_default()
            .push(Candidate { entry, access });
    }
    for ((kind, extension, _scope), mut candidates) in groups {
        candidates.sort_unstable_by(|a, b| {
            (a.entry.size, &a.entry.path).cmp(&(b.entry.size, &b.entry.path))
        });
        let mut family = Family {
            extension: extension.to_owned(),
            kind,
            files: candidates.len(),
            bytes: candidates.iter().map(|c| c.entry.size).sum(),
            samples: 0,
            sampled_bytes: 0,
            stored_bytes: 0,
            compress: false,
        };
        // Small mesh descriptors follow the family decision. Preserve the
        // sample of files with meaningful payloads when they are available.
        let first_large = candidates.partition_point(|c| c.entry.size < MIN_FILE_BYTES);
        let samples = if first_large == candidates.len() {
            &candidates[..]
        } else {
            &candidates[first_large..]
        };
        let count = samples.len().min(FILES_PER_FAMILY);
        let mut wins = 0;
        for sample in 0..count {
            let index = sample * (samples.len() - 1) / (count - 1).max(1);
            let (raw, stored) = sample_file(tree, samples[index].entry)?;
            family.samples += 1;
            family.sampled_bytes += raw;
            family.stored_bytes += stored;
            wins += usize::from(saves_enough(raw, stored));
        }
        family.compress =
            wins * 2 >= family.samples && saves_enough(family.sampled_bytes, family.stored_bytes);
        for candidate in candidates {
            if family.compress {
                result.selected.insert(
                    candidate.entry.path.clone(),
                    Evidence::Measured(candidate.access),
                );
                result.selected_bytes += candidate.entry.size;
            } else {
                result.leave(candidate.entry, "family samples show little savings");
            }
        }
        result.families.push(family);
    }
    cas.sort_unstable_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
    let mut cas_candidates = Vec::new();
    for (index, entry) in cas.into_iter().enumerate() {
        if index >= MAX_CAS_SAMPLES {
            result.leave(entry, "Frostbite CAS sampling limit reached");
            continue;
        }
        let (raw, stored) = sample_file(tree, entry)?;
        result.cas.samples += 1;
        result.cas.sampled_bytes += raw;
        result.cas.stored_bytes += stored;
        if !saves_enough(raw, stored) {
            result.leave(entry, "Frostbite CAS samples show little savings");
            continue;
        }
        result.cas.favorable += 1;
        if !findings.apr || findings.incomplete {
            result.leave(
                entry,
                "Frostbite CAS export requires APR and complete executable analysis",
            );
        } else {
            cas_candidates.push(entry);
        }
    }
    let include_cas = !cas_candidates.is_empty()
        && (findings.frostbite_cas_candidates || choose_frostbite_cas(cas_candidates.len())?);
    for entry in cas_candidates {
        if include_cas {
            result
                .selected
                .insert(entry.path.clone(), Evidence::Measured(Access::FrostbiteCas));
            result.selected_bytes += entry.size;
        } else {
            result.leave(entry, "Frostbite CAS test export was not enabled");
        }
    }
    Ok(result)
}

fn exclusion(entry: &Entry, kind: AssetKind, facts: &Findings<'_>) -> Option<&'static str> {
    let path = entry.path.as_str();
    if facts.keep.contains(path)
        || crate::protected_path(entry)
        || under_any(path, facts.blocked_scopes)
        || matches!(kind, AssetKind::Control | AssetKind::Media)
    {
        return Some("boot, control, executable, media or restricted I/O");
    }
    if entry.size < MIN_FILE_BYTES && kind != AssetKind::Payload(PayloadKind::SmbsMesh) {
        return Some("small file");
    }
    None
}

fn eligibility(
    entry: &Entry,
    kind: AssetKind,
    facts: &Findings<'_>,
) -> Result<(Option<PayloadKind>, Access), &'static str> {
    if let Some(reason) = exclusion(entry, kind, facts) {
        return Err(reason);
    }
    let path = entry.path.as_str();
    if !facts.apr || facts.incomplete {
        return Err("missing APR or incomplete executable analysis");
    }
    let asset = match kind {
        AssetKind::Payload(PayloadKind::AudioBank)
            if facts.aio || !under_any(path, facts.directory_scopes) =>
        {
            return Err("audio access remains uncertain");
        }
        AssetKind::Payload(asset) => Some(asset),
        _ => None,
    };
    if matches!(asset, Some(PayloadKind::Archive)) {
        return Err("container contents remain incompletely understood");
    }
    if facts.direct.contains(path) && !facts.aio {
        return Ok((asset, Access::AprArgument));
    }
    if asset.is_none() {
        return Err("unidentified payload");
    }
    if facts.catalogue.contains(path) {
        return Ok((asset, Access::Catalogue));
    }
    // An unresolved native AIO call limits selection to actual catalogue
    // members. It cannot justify expanding a rule to nearby files.
    if !facts.aio && under_any(path, facts.apr_scopes) {
        return Ok((asset, Access::AprScope));
    }
    Err("no linked APR or catalogue evidence")
}

pub(crate) fn in_scope(path: &str, directory: &str) -> bool {
    path.strip_prefix(directory)
        .is_some_and(|tail| tail.starts_with('/'))
}

fn under_any(path: &str, scopes: &BTreeSet<String>) -> bool {
    path.match_indices('/')
        .any(|(i, _)| scopes.contains(&path[..i]))
}

fn extension(path: &str) -> &str {
    path.rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .map_or("", |(_, ext)| ext)
}

// Keep unlike asset trees out of the same economic sample. This does not
// transfer access evidence between members of a stratum.
fn stratum(path: &str) -> String {
    path.split('/').take(2).collect::<Vec<_>>().join("/")
}

fn sample_file(tree: &mut (impl SourceTree + ?Sized), entry: &Entry) -> io::Result<(u64, u64)> {
    let length = entry.size.min(SAMPLE_BYTES);
    let last = entry.size - length;
    let offsets = BTreeSet::from([0, last / 2, last]);
    let mut stored = 0;
    for &offset in &offsets {
        let data = tree.read_range(&entry.path, offset, length as usize)?;
        if data.len() as u64 != length {
            return Err(invalid(format!("short compression sample: {}", entry.path)));
        }
        let compressed = compress_to_vec(data.as_slice(), CompressionLevel::Fastest);
        stored += length.min(compressed.len() as u64);
    }
    Ok((length * offsets.len() as u64, stored))
}

fn saves_enough(raw: u64, stored: u64) -> bool {
    raw != 0 && u128::from(stored) * 100 <= u128::from(raw) * u128::from(100 - MIN_SAVINGS)
}

impl PolicyResult {
    fn leave(&mut self, file: &Entry, reason: &'static str) {
        self.reasons.insert(file.path.clone(), reason);
        let (count, bytes) = self.loose.entry(reason).or_default();
        *count += 1;
        *bytes += file.size;
    }

    pub(crate) fn report(&self, out: &mut String) {
        writeln!(out, "\nEconomic candidate samples (not compatibility): ruzstd 0.8.1 Fastest; strata by format, extension and first two path components; up to {FILES_PER_FAMILY} files and 3 x {SAMPLE_BYTES} bytes per file; minimum savings {MIN_SAVINGS}%. Not a Forge level-5 pack-size measurement.").unwrap();
        for f in &self.families {
            let percentage = (f.sampled_bytes - f.stored_bytes) * 100 / f.sampled_bytes;
            let action = if f.compress { "compress" } else { "loose" };
            writeln!(out, "  .{} {:?}: {action}; {} files, {} raw bytes; {} sampled files, {}% sample savings.",
                f.extension, f.kind, f.files, f.bytes, f.samples, percentage).unwrap();
        }
        let cas = &self.cas;
        if cas.files > 0 {
            writeln!(
                out,
                "Frostbite CAS: {} archives ({} raw bytes). Sampled {} archives (up to {MAX_CAS_SAMPLES}, largest first). {} met the {MIN_SAVINGS}% savings threshold.",
                cas.files, cas.bytes, cas.samples, cas.favorable
            )
            .unwrap();
            if cas.sampled_bytes > 0 {
                let percentage = (cas.sampled_bytes - cas.stored_bytes) * 100 / cas.sampled_bytes;
                writeln!(out, "  {percentage}% savings across sampled bytes. Runtime read paths are unverified. CAS export is optional in guided mode and uses --frostbite-cas-candidates on the command line.").unwrap();
            }
        }
        for (reason, (files, bytes)) in &self.loose {
            writeln!(out, "Loose ({reason}): {files} files, {bytes} bytes.").unwrap();
        }
    }
}
