//! Offline analysis and reproducible profiles for AMPR Zstd.
//!
//! The full analysis combines access evidence with measured compression.
//! Selection is reproducible and gameplay validation takes place on PS5.

mod assets;
pub mod audit;
pub mod certificate;
mod code;
pub mod economics;
mod elf;
pub mod forge;
mod manifest;
mod policy;
mod source;
pub mod trace;

pub use source::{Entry, FolderSource, SourceTree};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io;

use code::Api;
use manifest::{Catalog, Paths};
use policy::PolicyResult;
use source::invalid;

const MAX_EXECUTABLE: u64 = 384 * 1024 * 1024;
const MAX_MANIFEST: u64 = 8 * 1024 * 1024;
const HEADER_BYTES: usize = 80;
const MAX_GLOB_PATTERNS: usize = 10_000;
const MIN_GROUP_FILES: usize = 64;

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Read the prefix of each file to also discover extensionless SELF/ELF
    /// and recognize binary catalogues whose name has an unusual extension.
    pub scan_headers: bool,
    /// Add exact paths named by recognized catalogues in APR titles.
    pub manifest_candidates: bool,
    /// Inspect every header and measure eligible payload families.
    pub full: bool,
    /// Include individually sampled Frostbite CAS archives in test candidates.
    /// Requires full mode and does not establish runtime read compatibility.
    pub frostbite_cas_candidates: bool,
    /// Export heuristic candidates as the active profile. Never a compatibility
    /// claim; default false leaves unresolved access physical.
    pub exploratory: bool,
}

impl Options {
    pub fn full() -> Self {
        Self {
            full: true,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Progress {
    Headers { checked: usize, total: usize },
    CodeAndCatalogues,
    CompressionSamples,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Evidence {
    AprLiteral,
    Catalogue(Catalog),
    Measured(policy::Access),
}

#[derive(Default)]
struct BinaryFacts {
    imports: usize,
    calls: BTreeMap<Api, (usize, u64)>,
    literals: BTreeSet<String>,
    directory_opens: usize,
    scope_refs: BTreeMap<(Api, String), (u8, u64)>,
    incomplete: bool,
    unresolved_indirect_calls: usize,
    unresolved_indirect_jumps: usize,
}

pub struct Analysis {
    pub files: usize,
    pub bytes: u64,
    pub selected_files: usize,
    pub selected_bytes: u64,
    pub header_count: usize,
    facts: BTreeMap<String, BinaryFacts>,
    catalogues: BTreeMap<String, (Catalog, usize)>,
    selected: BTreeMap<String, Evidence>,
    patterns: Vec<String>,
    manifest_candidates: bool,
    measured: Option<PolicyResult>,
    apr_scopes: BTreeSet<String>,
    odx_scopes: BTreeSet<String>,
    blocked_scopes: BTreeSet<String>,
    media_archives: usize,
    unclassified_archives: usize,
    inventory: Vec<Entry>,
    candidates: BTreeMap<String, Evidence>,
    decisions: BTreeMap<String, String>,
    exploratory: bool,
    archive_details: BTreeMap<String, String>,
}

pub struct Profile {
    pub toml: String,
    /// Optional lists referenced by `include_from`, to be saved beside the TOML.
    pub lists: BTreeMap<String, String>,
}

pub fn analyze(tree: &mut (impl SourceTree + ?Sized), options: Options) -> io::Result<Analysis> {
    analyze_with_progress(tree, options, |_| {})
}

pub fn analyze_with_progress(
    tree: &mut (impl SourceTree + ?Sized),
    options: Options,
    mut progress: impl FnMut(Progress),
) -> io::Result<Analysis> {
    if options.full && options.manifest_candidates {
        return Err(invalid(
            "full scan and manifest-only policy are mutually exclusive",
        ));
    }
    if options.frostbite_cas_candidates && !options.full {
        return Err(invalid("--frostbite-cas-candidates requires full mode"));
    }
    let mut files = tree.files().to_vec();
    files.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    let mut folded_paths = BTreeSet::new();
    let mut bytes = 0u64;
    for f in &files {
        if f.path.contains(['\\', ':'])
            || f.path.chars().any(char::is_control)
            || f.path
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
            || !folded_paths.insert(f.path.to_ascii_lowercase())
        {
            return Err(invalid(format!(
                "invalid or case-colliding path: {}",
                f.path
            )));
        }
        bytes = bytes
            .checked_add(f.size)
            .ok_or_else(|| invalid("dump size overflow"))?;
    }
    let paths = Paths::new(&files);
    let mut facts = BTreeMap::new();
    let mut catalogues = BTreeMap::new();
    let mut catalogued = BTreeMap::new();
    let mut direct = BTreeSet::new();
    let mut keep = BTreeSet::new();
    let mut apr_scopes = BTreeSet::new();
    let mut directory_scopes = BTreeSet::new();
    let mut odx_scopes = BTreeSet::new();
    let mut blocked_scopes = BTreeSet::new();
    let directories: BTreeSet<_> = if options.full {
        files
            .iter()
            .flat_map(|entry| {
                entry
                    .path
                    .match_indices('/')
                    .map(|(index, _)| &entry.path[..index])
            })
            .collect()
    } else {
        BTreeSet::new()
    };
    let scan_all = options.scan_headers || options.full;
    let mut headers = Vec::new();
    let mut kinds = Vec::new();
    let mut media_archives = 0;
    let mut unclassified_archives = 0;
    let mut archive_details = BTreeMap::new();
    if scan_all {
        progress(Progress::Headers {
            checked: 0,
            total: files.len(),
        });
        for entries in files.chunks(4096) {
            let batch = tree.read_headers(entries, HEADER_BYTES)?;
            if batch.len() != entries.len() {
                return Err(invalid("header batch returned the wrong number of files"));
            }
            for (entry, head) in entries.iter().zip(&batch) {
                if head.len() != entry.size.min(HEADER_BYTES as u64) as usize {
                    return Err(invalid(format!("short header: {}", entry.path)));
                }
            }
            headers.extend(batch);
            progress(Progress::Headers {
                checked: headers.len(),
                total: files.len(),
            });
        }
    }
    let frostbite = options.full
        && files.iter().zip(&headers).any(|(entry, header)| {
            entry.path.eq_ignore_ascii_case("data/layout.toc")
                && assets::frostbite_layout(header, entry.size)
        });
    progress(Progress::CodeAndCatalogues);
    for (index, f) in files.iter().enumerate() {
        let lower = f.path.to_ascii_lowercase();
        // Build identifiers commonly occur beyond the first 80 bytes.
        if lower == "sce_sys/param.json" {
            if f.size > MAX_MANIFEST {
                return Err(invalid("build metadata exceeds 8 MiB budget"));
            }
            read(tree, f, f.size as usize)?;
        }
        let executable_name = lower == "eboot.bin"
            || [".elf", ".self", ".prx", ".sprx"]
                .iter()
                .any(|ext| lower.ends_with(ext));
        let catalogue_name = lower.ends_with(".pgm") || lower.ends_with(".xml");
        let partial;
        let head: &[u8] = if scan_all {
            headers[index].as_slice()
        } else if f.size > 0 && (executable_name || catalogue_name) {
            partial = read(tree, f, f.size.min(HEADER_BYTES as u64) as usize)?;
            &partial
        } else {
            &[]
        };
        if options.full {
            let kind = if head.starts_with(b"cral") {
                let inspection = assets::inspect_larc(tree, f, head)?;
                archive_details.insert(f.path.clone(), format!("{inspection:?}"));
                match inspection.status {
                    assets::LarcStatus::Media => {
                        media_archives += 1;
                        assets::AssetKind::Media
                    }
                    _ => {
                        unclassified_archives += 1;
                        assets::AssetKind::Control
                    }
                }
            } else {
                let kind = assets::classify(&f.path, f.size, head);
                if kind == assets::AssetKind::Unknown
                    && frostbite
                    && assets::frostbite_cas_path(&lower)
                {
                    assets::AssetKind::FrostbiteCas
                } else {
                    kind
                }
            };
            kinds.push(kind);
        }
        if external_media_magic(head) {
            keep.insert(f.path.as_str());
        }
        if executable_name || elf::executable_magic(head) {
            keep.insert(f.path.as_str());
            let mut out = BinaryFacts::default();
            if f.size <= MAX_EXECUTABLE {
                let data = read(tree, f, f.size as usize)?;
                if let Some(image) = elf::Image::parse(&data) {
                    out.imports = image.imports.len();
                    out.incomplete = image.inaccessible_code || image.code().next().is_none();
                    let io = code::inspect(&image, |path| {
                        options.full
                            && (paths.lookup(path).is_some()
                                || directories.contains(dump_relative(path)))
                    });
                    out.unresolved_indirect_calls = io.unresolved_indirect_calls.len();
                    out.unresolved_indirect_jumps = io.unresolved_indirect_jumps.len();
                    for call in io.calls {
                        out.calls.entry(call.api).or_insert((0, call.rva)).0 += 1;
                        if call.is_directory_open() {
                            out.directory_opens += 1;
                        }
                        for path in call
                            .paths
                            .iter()
                            .filter_map(|path| paths.exact_argument(path))
                        {
                            match call.api {
                                Api::AprResolve => {
                                    direct.insert(path);
                                }
                                Api::Video | Api::Aio => {
                                    keep.insert(path);
                                }
                                _ => {}
                            }
                        }
                    }
                    for reference in io.references {
                        let relative = dump_relative(reference.path);
                        let is_directory = directories.contains(relative);
                        for (api, distance) in reference.distances {
                            let scopes = match api {
                                Api::Aio | Api::Video if distance <= 1 => {
                                    keep.extend(paths.lookup(reference.path));
                                    &mut blocked_scopes
                                }
                                Api::AprRead if relative.contains('/') => &mut apr_scopes,
                                Api::Directory
                                    if distance <= 2
                                        && out.calls.contains_key(&Api::Directory)
                                        && out.directory_opens != 0 =>
                                {
                                    &mut directory_scopes
                                }
                                _ => continue,
                            };
                            if is_directory {
                                scopes.insert(relative.to_owned());
                                let candidate = (distance, reference.rva);
                                let best = out
                                    .scope_refs
                                    .entry((api, relative.to_owned()))
                                    .or_insert(candidate);
                                *best = (*best).min(candidate);
                            }
                        }
                    }
                    out.literals = image
                        .literals()
                        .iter()
                        .filter_map(|s| paths.lookup(s))
                        .take(25)
                        .map(str::to_owned)
                        .collect();
                } else {
                    out.incomplete = true;
                }
            } else {
                out.incomplete = true;
            }
            facts.insert(f.path.clone(), out);
        } else if (catalogue_name || manifest::has_catalogue_header(head)) && f.size <= MAX_MANIFEST
        {
            let contents = read(tree, f, f.size as usize)?;
            if let Some((kind, references)) = manifest::references(&contents, &paths) {
                keep.insert(f.path.as_str());
                catalogues.insert(f.path.clone(), (kind, references.len()));
                if kind == Catalog::OdxPaths {
                    if let Some((parent, _)) = f.path.rsplit_once('/') {
                        let covered = references
                            .iter()
                            .filter(|path| policy::in_scope(path, parent))
                            .count();
                        if covered >= 8 && covered * 4 >= references.len() * 3 {
                            odx_scopes.insert(parent.to_owned());
                            if options.full {
                                keep.extend(references.iter().copied());
                            }
                        }
                    }
                }
                for name in references {
                    catalogued.entry(name).or_insert(kind);
                }
            }
        }
    }
    let has_call = |api| facts.values().any(|b| b.calls.contains_key(&api));
    let incomplete = !facts.contains_key("eboot.bin") || facts.values().any(|b| b.incomplete);
    let apr = has_call(Api::AprResolve) && has_call(Api::AprRead);
    let unresolved_aio = has_call(Api::Aio);
    let mut selected = BTreeMap::new();
    let mut selected_bytes = 0;
    let measured = if options.full {
        progress(Progress::CompressionSamples);
        let mut result = policy::select(
            tree,
            &files,
            &kinds,
            policy::Findings {
                apr,
                incomplete,
                aio: unresolved_aio,
                directory_scopes: &directory_scopes,
                direct: &direct,
                catalogue: &catalogued.keys().copied().collect(),
                apr_scopes: &apr_scopes,
                keep: &keep,
                blocked_scopes: &blocked_scopes,
                frostbite_cas_candidates: options.frostbite_cas_candidates,
            },
        )?;
        selected = std::mem::take(&mut result.selected);
        selected_bytes = result.selected_bytes;
        Some(result)
    } else {
        None
    };
    if !options.full && apr && (!incomplete || options.manifest_candidates) {
        for f in &files {
            if keep.contains(f.path.as_str()) || keep_loose(f) {
                continue;
            }
            let evidence = if direct.contains(f.path.as_str()) && !unresolved_aio {
                Some(Evidence::AprLiteral)
            } else if options.manifest_candidates {
                catalogued
                    .get(f.path.as_str())
                    .copied()
                    .map(Evidence::Catalogue)
            } else {
                None
            };
            if let Some(evidence) = evidence {
                selected.insert(f.path.clone(), evidence);
                selected_bytes += f.size;
            }
        }
    }
    // Resolver arguments, graph scopes and catalogue membership are hypotheses,
    // not a demonstrated path -> read -> completion chain. Keep the economic
    // candidate set inspectable without silently authorizing it.
    let candidates = selected.clone();
    let mut decisions = BTreeMap::new();
    for f in &files {
        let reason = if let Some(evidence) = candidates.get(&f.path) {
            format!(
                "inconclusive access; heuristic={evidence:?}; economy={}",
                if measured.is_some() {
                    "sample favorable"
                } else {
                    "not measured"
                }
            )
        } else if let Some(reason) = measured.as_ref().and_then(|m| m.reasons.get(&f.path)) {
            reason.to_string()
        } else if keep.contains(f.path.as_str()) || protected_path(f) {
            "physical precaution: boot, control, executable or media".into()
        } else {
            "inconclusive access: no proven consumer/read chain".into()
        };
        decisions.insert(f.path.clone(), reason);
    }
    if !options.exploratory {
        selected.clear();
        selected_bytes = 0;
    }
    let patterns = if options.full {
        compact_patterns(&files, &selected)
    } else {
        selected.keys().map(|path| literal_pattern(path)).collect()
    };
    Ok(Analysis {
        files: files.len(),
        bytes,
        selected_files: selected.len(),
        selected_bytes,
        header_count: headers.len(),
        facts,
        catalogues,
        selected,
        patterns,
        manifest_candidates: options.manifest_candidates,
        measured,
        apr_scopes,
        odx_scopes,
        blocked_scopes,
        media_archives,
        unclassified_archives,
        inventory: files,
        candidates,
        decisions,
        exploratory: options.exploratory,
        archive_details,
    })
}

fn dump_relative(path: &str) -> &str {
    path.strip_prefix("/app0/")
        .unwrap_or(path)
        .trim_matches('/')
}

fn read(tree: &mut (impl SourceTree + ?Sized), entry: &Entry, len: usize) -> io::Result<Vec<u8>> {
    let data = tree.read_range(&entry.path, 0, len)?;
    if data.len() != len {
        return Err(invalid(format!("short read: {}", entry.path)));
    }
    Ok(data)
}

fn external_media_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"XVAG")
        || bytes.starts_with(b"BIK")
        || bytes.starts_with(b"KB2")
        || bytes.get(4..8) == Some(b"ftyp")
        || bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WAVE")
}

fn protected_path(entry: &Entry) -> bool {
    let path = entry.path.to_ascii_lowercase();
    let name = path.rsplit('/').next().unwrap_or(&path);
    let ext = name.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    entry.size == 0
        || !path.contains('/')
        || path.starts_with("sce_sys/")
        || path.starts_with("sce_module/")
        || path.starts_with("fakelib")
        || name == "eboot.bin"
        || name.starts_with("pgc_") && name.ends_with("_dummy_file")
        || matches!(
            ext,
            "elf"
                | "self"
                | "prx"
                | "sprx"
                | "esbak"
                | "pgm"
                | "xml"
                | "json"
                | "toml"
                | "ini"
                | "log"
                | "mp4"
                | "bsf"
                | "bik"
                | "bk2"
                | "usm"
                | "webm"
                | "at9"
                | "xvag"
                | "wav"
                | "wem"
                | "mid"
                | "bus"
                | "dml"
                | "gmx"
                | "texmeshman"
                | "packman"
        )
}

fn keep_loose(entry: &Entry) -> bool {
    protected_path(entry)
        || matches!(
            entry
                .path
                .rsplit_once('.')
                .map(|(_, ext)| ext.to_ascii_lowercase())
                .as_deref(),
            Some("szd" | "szd1" | "szd2")
        )
}

fn compact_patterns(files: &[Entry], selected: &BTreeMap<String, Evidence>) -> Vec<String> {
    let mut groups = BTreeMap::<(&str, &str), (usize, usize)>::new();
    // Forge's '*' also matches '/', so count every descendant with the
    // extension before allowing a wildcard for a directory.
    for file in files {
        let Some(extension) = pattern_extension(&file.path) else {
            continue;
        };
        let included =
            usize::from(selected.get(&file.path).is_some_and(|evidence| {
                *evidence != Evidence::Measured(policy::Access::FrostbiteCas)
            }));
        for (index, _) in file.path.match_indices('/') {
            let (total, packed) = groups.entry((&file.path[..index], extension)).or_default();
            *total += 1;
            *packed += included;
        }
    }
    let mut patterns = BTreeSet::new();
    for path in selected.keys() {
        if selected[path] == Evidence::Measured(policy::Access::FrostbiteCas) {
            patterns.insert(literal_pattern(path));
            continue;
        }
        let group = pattern_extension(path).and_then(|extension| {
            path.match_indices('/').rev().find_map(|(index, _)| {
                let directory = &path[..index];
                let (total, packed) = groups[&(directory, extension)];
                (total == packed && total >= MIN_GROUP_FILES).then_some((directory, extension))
            })
        });
        let pattern = match group {
            Some((directory, extension)) => format!("{}/*.{extension}", literal_pattern(directory)),
            None => literal_pattern(path),
        };
        patterns.insert(pattern);
    }
    if patterns.iter().filter(|pattern| is_glob(pattern)).count() > MAX_GLOB_PATTERNS {
        return selected.keys().map(|path| literal_pattern(path)).collect();
    }
    patterns.into_iter().collect()
}

fn pattern_extension(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    let (_, extension) = name.rsplit_once('.')?;
    (!extension.is_empty() && extension.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then_some(extension)
}

fn is_glob(pattern: &str) -> bool {
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '[' => {
                // Generated bracket expressions always escape one literal.
                chars.nth(1);
            }
            '*' => return true,
            _ => {}
        }
    }
    false
}

impl Analysis {
    pub fn profile(&self) -> io::Result<Profile> {
        self.render_profile(&self.patterns, self.selected_files, self.exploratory)
    }

    /// Explicitly experimental hypotheses, kept separate from the safe output.
    pub fn candidate_profile(&self) -> io::Result<Profile> {
        let patterns = compact_patterns(&self.inventory, &self.candidates);
        self.render_profile(&patterns, self.candidates.len(), true)
    }

    pub fn selected_paths(&self) -> BTreeSet<String> {
        self.selected.keys().cloned().collect()
    }

    pub fn candidate_paths(&self) -> BTreeSet<String> {
        self.candidates.keys().cloned().collect()
    }

    pub fn inventory(&self) -> &[Entry] {
        &self.inventory
    }

    /// Every row has an explicit decision; TSV paths cannot contain controls.
    pub fn decisions_tsv(&self) -> String {
        let mut out = String::from("path\tsize\taction\tcompatibility\treason\tcontainer\n");
        for f in &self.inventory {
            let action = if self.selected.contains_key(&f.path) {
                "compress-experimental"
            } else {
                "loose"
            };
            writeln!(
                out,
                "{}\t{}\t{}\tunvalidated\t{}\t{}",
                f.path,
                f.size,
                action,
                self.decisions[&f.path],
                self.archive_details
                    .get(&f.path)
                    .map(String::as_str)
                    .unwrap_or("-")
            )
            .unwrap();
        }
        out
    }

    fn render_profile(
        &self,
        patterns: &[String],
        count: usize,
        exploratory: bool,
    ) -> io::Result<Profile> {
        let mut toml = format!(
            "# ps5-pack-analyzer v{} | ampr-emu-ng 0.3.2\n",
            env!("CARGO_PKG_VERSION")
        );
        let mode = if self.measured.is_some() {
            "full scan, static evidence and measured family savings"
        } else if self.manifest_candidates {
            "manifest candidates (experimental)"
        } else {
            "direct APR evidence"
        };
        writeln!(toml, "# Mode: {mode}. Verify gameplay on PS5.").unwrap();
        if exploratory {
            toml.push_str(
                "# EXPERIMENTAL CANDIDATES ONLY: access is inconclusive; not console validated.\n",
            );
        } else {
            toml.push_str("# Conservative policy: unresolved consumers remain physical.\n");
        }
        if exploratory
            && self
                .candidates
                .values()
                .any(|evidence| *evidence == Evidence::Measured(policy::Access::FrostbiteCas))
        {
            toml.push_str("# Frostbite CAS candidates use sampled savings. Their runtime read paths are unverified.\n");
        }
        if self
            .facts
            .values()
            .any(|facts| facts.calls.contains_key(&Api::Aio))
        {
            toml.push_str("# Kernel AIO found with unresolved targets. Review report.txt.\n");
        }
        if count == 0 {
            toml.push_str("# No pack candidates were established.\n");
        }
        if patterns.len() < count {
            toml.push_str("# Directory patterns were verified against this inventory. Re-scan changed dumps.\n");
        }
        toml.push_str("[pack]\ndefault_action = \"loose\"\n");
        let mut lists = BTreeMap::new();
        if count == 0 {
            return Ok(Profile { toml, lists });
        }
        let wildcard_count = patterns.iter().filter(|pattern| is_glob(pattern)).count();
        if wildcard_count > MAX_GLOB_PATTERNS || patterns.len() > 200_000 {
            return Err(invalid("profile exceeds Dump Forge pattern limits"));
        }
        toml.push_str("\n[[rule]]\naction = \"compress\"\n");
        let mut inline = String::new();
        for pattern in patterns {
            writeln!(inline, "  {},", toml_string(pattern)).unwrap();
        }
        if inline.len() <= 960_000 {
            writeln!(toml, "include = [\n{inline}]").unwrap();
        } else {
            let mut part = String::new();
            let mut length = 0usize;
            for pattern in patterns {
                if pattern.len() + 1 > 960_000 {
                    return Err(invalid("profile pattern exceeds Dump Forge list size"));
                }
                if part.len() + pattern.len() + 1 > 960_000 {
                    push_part(&mut lists, &mut part);
                }
                writeln!(part, "{pattern}").unwrap();
                length += pattern.len() + 1;
            }
            push_part(&mut lists, &mut part);
            if length > 16 * 1024 * 1024 {
                return Err(invalid("profile lists exceed Dump Forge total list size"));
            }
            toml.push_str("include_from = [\n");
            for name in lists.keys() {
                writeln!(toml, "  \"{name}\",").unwrap();
            }
            toml.push_str("]\n");
        }
        Ok(Profile { toml, lists })
    }

    pub fn report(&self) -> String {
        let mut out = String::new();
        writeln!(
            out,
            "Files: {} ({} bytes). Headers scanned: {}.",
            self.files, self.bytes, self.header_count
        )
        .unwrap();
        writeln!(
            out,
            "Active selection: {} ({} raw bytes). Loose: {}.",
            self.selected_files,
            self.selected_bytes,
            self.files - self.selected_files
        )
        .unwrap();
        writeln!(out, "Heuristic economic candidates: {}. Conservative policy does not promote resolver arguments, graph scopes or catalogues to compatible reads. Experimental export: {}.", self.candidates.len(), self.exploratory).unwrap();
        for (path, facts) in &self.facts {
            writeln!(
                out,
                "\n{path}: {} imported slots; incomplete executable view: {}",
                facts.imports, facts.incomplete
            )
            .unwrap();
            for (api, &(count, first)) in &facts.calls {
                writeln!(out, "  {api:?}: {count} call sites; first RVA {first:#x}").unwrap();
            }
            writeln!(
                out,
                "  Unresolved indirect calls: {}; jumps: {}. These may or may not be I/O.",
                facts.unresolved_indirect_calls, facts.unresolved_indirect_jumps
            )
            .unwrap();
            writeln!(
                out,
                "  Open calls with a statically known O_DIRECTORY bit: {}",
                facts.directory_opens
            )
            .unwrap();
            for path in &facts.literals {
                writeln!(out, "  literal present in dump: {path}").unwrap();
            }
            for ((api, path), (distance, rva)) in &facts.scope_refs {
                writeln!(out, "  {api:?} scope reference: {path}/ at RVA {rva:#x}; {distance} direct call edges.").unwrap();
            }
        }
        for (path, (kind, references)) in &self.catalogues {
            writeln!(
                out,
                "Catalogue {path} ({kind:?}): {references} matching paths."
            )
            .unwrap();
        }
        if let Some(measured) = &self.measured {
            if self.media_archives != 0 || self.unclassified_archives != 0 {
                writeln!(
                    out,
                    "LARC archives kept loose: {} with media evidence, {} with incomplete content coverage.",
                    self.media_archives, self.unclassified_archives
                )
                .unwrap();
            }
            for scope in &self.apr_scopes {
                writeln!(out, "APR code scope: {scope}/").unwrap();
            }
            for scope in &self.odx_scopes {
                writeln!(
                    out,
                    "ODX resident catalogue members protected under: {scope}/"
                )
                .unwrap();
            }
            for scope in &self.blocked_scopes {
                writeln!(out, "Restricted I/O scope: {scope}/").unwrap();
            }
            measured.report(&mut out);
        }
        let mut counts = BTreeMap::new();
        for evidence in self.selected.values() {
            *counts.entry(*evidence).or_insert(0) += 1;
        }
        for (evidence, count) in counts {
            writeln!(out, "Selection evidence {evidence:?}: {count} files.").unwrap();
        }
        if self.facts.values().any(|f| f.calls.contains_key(&Api::Aio)) {
            out.push_str("Kernel AIO has unresolved destinations. It cannot read packed virtual descriptors.\n");
        }
        if self.selected.is_empty() {
            out.push_str("No files selected for compression.\n");
        }
        out.push_str("Catalogue membership does not establish which API consumes a file. Static analysis does not exercise gameplay.\n");
        out.push_str("Dynamic resolution, mapping, callbacks and unexamined modules can hide additional consumers. No absence-of-I/O claim is made.\n");
        let small: Vec<_> = self
            .inventory
            .iter()
            .filter(|f| f.size > 0 && f.size < 2048)
            .collect();
        let logical: u64 = small.iter().map(|f| f.size).sum();
        writeln!(out, "Small files (<2048 bytes): {}; {} logical bytes. Allocation scenarios (not measured filesystem usage):", small.len(), logical).unwrap();
        for unit in [4096u64, 32768, 131072] {
            let allocated: u64 = small.iter().map(|f| f.size.div_ceil(unit) * unit).sum();
            writeln!(
                out,
                "  unit={unit}: allocated={allocated}; slack={}",
                allocated - logical
            )
            .unwrap();
        }
        out
    }
}

fn push_part(lists: &mut BTreeMap<String, String>, part: &mut String) {
    lists.insert(
        format!("paths-{:03}.txt", lists.len() + 1),
        std::mem::take(part),
    );
}

fn literal_pattern(path: &str) -> String {
    let last = path.trim_end().len();
    let first = path.len() - path.trim_start().len();
    let mut out = String::new();
    for (i, c) in path.char_indices() {
        match c {
            '[' => out.push_str("[[]"),
            '*' => out.push_str("[*]"),
            '?' => out.push_str("[?]"),
            '#' if i == 0 => out.push_str("[#]"),
            c if c.is_whitespace() && (i < first || i >= last) => {
                out.push('[');
                out.push(c);
                out.push(']');
            }
            _ => out.push(c),
        }
    }
    out
}

fn toml_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => write!(out, "\\u{:04X}", c as u32).unwrap(),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_literal_pattern_escapes_from_wildcards() {
        assert!(!is_glob(&literal_pattern(" [*?]/file ")));
        assert!(is_glob(&format!("{}/*.bin", literal_pattern("assets[*]"))));
    }
}
