use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ps5_pack_analyzer::{
    analyze_with_progress,
    audit::AuditedSource,
    certificate::{self, Certificate},
    FolderSource, Options, Profile, Progress,
};
use std::collections::{BTreeMap, BTreeSet};

mod interactive;

const USAGE: &str = "ps5-pack-analyzer <dump-folder> <new-output-folder> [--full | --strict | --manifest-candidates] [--headers] [--full-hash] [--frostbite-cas-candidates]\n\
  ps5-pack-analyzer --verify <dump-folder> <analysis-folder>\n\
  ps5-pack-analyzer --trace <trace.tsv> <certificate.txt>\n\
  ps5-pack-analyzer --interactive\n\
  ps5-pack-analyzer --version\n\
  --full                 Scan all headers and measure eligible families (default)\n\
  --strict               Inspect resolver arguments; unresolved reads remain loose\n\
  --manifest-candidates  Use the catalogue-only experimental policy from v0.1\n\
  --headers              Also scan all headers in either diagnostic mode\n\
  --full-hash            Cover every input byte in the profile certificate\n\
  --frostbite-cas-candidates  Add sampled Frostbite CAS archives for console testing (full mode)\n\
  Writes one experimental profile when there are compression candidates. Validate it on a PS5.";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    let Some(input) = args.next() else {
        println!("{USAGE}");
        return Ok(());
    };
    if input == "--help" || input == "-h" {
        println!("{USAGE}");
        return Ok(());
    }
    if input == "--version" || input == "--interactive" {
        if args.next().is_some() {
            return Err(argument(USAGE));
        }
        if input == "--version" {
            println!("ps5-pack-analyzer {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        return interactive::run();
    }
    if input == "--verify" {
        let dump = PathBuf::from(args.next().ok_or_else(|| argument(USAGE))?);
        let output = PathBuf::from(args.next().ok_or_else(|| argument(USAGE))?);
        if args.next().is_some() {
            return Err(argument(USAGE));
        }
        let (profile, selected, certificate) = load_artifact(&output)?;
        certificate.verify(&mut FolderSource::open(&dump)?, &selected, &profile)?;
        println!("Verified inventory, selection, profile and recorded evidence ranges. This does not validate PS5 gameplay or unread bytes.");
        return Ok(());
    }
    if input == "--trace" {
        let trace_path = PathBuf::from(args.next().ok_or_else(|| argument(USAGE))?);
        let cert_path = PathBuf::from(args.next().ok_or_else(|| argument(USAGE))?);
        if args.next().is_some() {
            return Err(argument(USAGE));
        }
        let trace =
            ps5_pack_analyzer::trace::Trace::parse(&read_bounded(&trace_path, 64 * 1024 * 1024)?)
                .map_err(|e| argument(e.to_string()))?;
        trace
            .bind_certificate(&read_bounded(&cert_path, MAX_ARTIFACT_BYTES)?)
            .map_err(|e| argument(e.to_string()))?;
        print!("{}", trace.report());
        return Ok(());
    }
    let output = PathBuf::from(args.next().ok_or_else(|| argument(USAGE))?);
    let mut mode = None;
    let mut scan_headers = false;
    let mut full_hash = false;
    let mut frostbite_cas_candidates = false;
    for arg in args {
        if arg == "--exploratory" {
            // Older invocations used this flag to put candidates in the main profile.
            continue;
        }
        if arg == "--full-hash" {
            full_hash = true;
            continue;
        }
        if arg == "--headers" {
            scan_headers = true;
            continue;
        }
        if arg == "--frostbite-cas-candidates" {
            frostbite_cas_candidates = true;
            continue;
        }
        let options = if arg == "--full" {
            Options::full()
        } else if arg == "--strict" {
            Options::default()
        } else if arg == "--manifest-candidates" {
            Options {
                manifest_candidates: true,
                ..Options::default()
            }
        } else {
            return Err(argument(format!("unknown option {arg:?}\n{USAGE}")));
        };
        if mode.replace(options).is_some() {
            return Err(argument("select only one analysis mode"));
        }
    }
    let mut options = mode.unwrap_or_else(Options::full);
    options.scan_headers = scan_headers;
    options.frostbite_cas_candidates = frostbite_cas_candidates;
    analyze_dump(&PathBuf::from(input), &output, options, full_hash, false)
}

fn check_output(source_root: &Path, output: &Path) -> io::Result<PathBuf> {
    let output_name = output
        .file_name()
        .ok_or_else(|| argument("invalid output folder"))?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent.canonicalize()?;
    if !fs::metadata(&parent)?.is_dir() {
        return Err(argument("output parent must be a directory"));
    }
    let output = parent.join(output_name);
    if output.starts_with(source_root) {
        return Err(argument("output must be outside the dump"));
    }
    if path_exists(&output)? {
        return Err(argument("output directory already exists"));
    }
    Ok(output)
}

fn path_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn analyze_dump(
    input: &Path,
    output: &Path,
    mut options: Options,
    full_hash: bool,
    guided: bool,
) -> io::Result<()> {
    let output = check_output(&input.canonicalize()?, output)?;
    let mut source = AuditedSource::new(FolderSource::open(input)?);
    let mut next_update = 0;
    options.exploratory = true;
    let result = analyze_with_progress(&mut source, options, |progress| match progress {
        Progress::Headers { checked, total } if checked >= next_update || checked == total => {
            eprintln!("Headers: {checked}/{total}");
            next_update = checked + 16_384;
        }
        Progress::CodeAndCatalogues => eprintln!("Analyzing executable I/O and catalogues"),
        Progress::CompressionSamples => eprintln!("Measuring Zstd savings on eligible families"),
        _ => {}
    })?;
    let selected = result.selected_paths();
    let full_hash = full_hash && !selected.is_empty();
    if full_hash {
        source.hash_all(|done, total| {
            if done % 16384 == 0 || done == total {
                eprintln!("Full byte coverage: {done}/{total}");
            }
        })?;
    }
    let decisions = result.decisions_tsv();
    let mut report = format!(
        "{}\nEvidence bytes read: {}.\n",
        result.report(),
        source.bytes_read
    );
    let selection_bytes: usize = selected.iter().map(|path| path.len() + 1).sum();
    if selection_bytes > MAX_SELECTION_BYTES {
        return Err(argument("selection exceeds 32 MiB verification limit"));
    }
    let artifacts = if selected.is_empty() {
        None
    } else {
        let profile = result.profile()?;
        let ranges = source.ranges()?;
        let certificate = certificate::create(result.inventory(), &selected, &profile, &ranges)?;
        eprintln!(
            "Reopening inventory and verifying recorded evidence before publishing artifacts"
        );
        certificate.verify(&mut FolderSource::open(input)?, &selected, &profile)?;
        report.push_str(&format!(
            "Full byte coverage recorded: {full_hash}.\nThe certificate checks the recorded ranges. Validate the profile on a PS5.\n"
        ));
        Some((profile, certificate.serialize()))
    };
    let profile_bytes = artifacts.as_ref().map_or(0, |(profile, cert)| {
        profile.toml.len() + cert.len() + profile.lists.values().map(String::len).sum::<usize>()
    });
    let bytes = decisions.len() + report.len() + selection_bytes + profile_bytes;
    if bytes > MAX_ARTIFACT_BYTES {
        return Err(argument("analysis artifacts exceed 256 MiB disk budget"));
    }
    check_free_space(output.parent().unwrap(), bytes as u64)?;
    fs::create_dir(&output)?;
    write_new(&output.join("report.txt"), &report)?;
    write_new(&output.join("decisions.tsv"), &decisions)?;
    if let Some((profile, cert)) = artifacts {
        save_profile(&output, &profile, &selected)?;
        // Write the certificate only after the full output has been written.
        save_certificate(&output, &cert)?;
    }
    if guided {
        interactive::print_summary(&output, selected.len());
    } else {
        println!(
            "{} files selected out of {} ({} raw bytes). Output {}",
            result.selected_files,
            result.files,
            result.selected_bytes,
            output.display()
        );
        if selected.is_empty() {
            println!("No compression candidates were found. See report.txt for the analysis.");
        } else {
            println!(
                "Use profile.toml to test compression in Forge and validate the result on a PS5."
            );
        }
    }
    Ok(())
}

const MAX_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;
const MAX_SELECTION_BYTES: usize = 32 * 1024 * 1024;

#[cfg(windows)]
fn check_free_space(parent: &Path, required: u64) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(
            path: *const u16,
            available: *mut u64,
            total: *mut u64,
            free: *mut u64,
        ) -> i32;
    }
    let path: Vec<u16> = parent.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut available = 0;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            path.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    eprintln!("Disk preflight: {available} bytes available; output budget {required} bytes; preserving 1 GiB reserve");
    if available < required.saturating_add(1024 * 1024 * 1024) {
        return Err(argument("insufficient disk headroom (1 GiB reserve)"));
    }
    Ok(())
}

#[cfg(not(windows))]
fn check_free_space(_parent: &Path, _required: u64) -> io::Result<()> {
    Ok(())
}

fn save_profile(dir: &Path, profile: &Profile, selected: &BTreeSet<String>) -> io::Result<()> {
    for (name, text) in &profile.lists {
        write_new(&dir.join(name), text)?;
    }
    let mut paths = String::new();
    for path in selected {
        paths.push_str(path);
        paths.push('\n');
    }
    write_new(&dir.join("selected.txt"), &paths)?;
    write_new(&dir.join("profile.toml"), &profile.toml)
}

fn save_certificate(dir: &Path, text: &str) -> io::Result<()> {
    // A truncated file can end after a complete range and still parse.
    // Extend it with zeros first so any unwritten tail fails parsing.
    let mut file = fs::File::create_new(dir.join("certificate.txt"))?;
    file.set_len(text.len() as u64)?;
    file.write_all(text.as_bytes())
}

fn read_bounded(path: &Path, limit: usize) -> io::Result<String> {
    use std::io::Read;
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > limit as u64 {
        return Err(argument("artifact exceeds read limit"));
    }
    let mut text = String::new();
    file.take(limit as u64 + 1).read_to_string(&mut text)?;
    if text.len() > limit {
        return Err(argument("artifact grew beyond read limit"));
    }
    Ok(text)
}

fn load_artifact(dir: &Path) -> io::Result<(Profile, BTreeSet<String>, Certificate)> {
    let toml = read_bounded(&dir.join("profile.toml"), 1024 * 1024).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                error.kind(),
                format!("no profile.toml found in {}", dir.display()),
            )
        } else {
            error
        }
    })?;
    let mut lists = BTreeMap::new();
    let mut total = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("paths-") && name.ends_with(".txt") {
            let value = read_bounded(&entry.path(), 1024 * 1024)?;
            total += value.len();
            if total > 16 * 1024 * 1024 {
                return Err(argument("pattern lists exceed 16 MiB"));
            }
            lists.insert(name, value);
        }
    }
    let paths = read_bounded(&dir.join("selected.txt"), MAX_SELECTION_BYTES)?;
    let selected: BTreeSet<String> = paths.lines().map(str::to_owned).collect();
    if selected.len() != paths.lines().count() {
        return Err(argument("duplicate selection paths"));
    }
    let cert = Certificate::parse(&read_bounded(
        &dir.join("certificate.txt"),
        MAX_ARTIFACT_BYTES,
    )?)?;
    Ok((Profile { toml, lists }, selected, cert))
}

fn write_new(path: &Path, text: &str) -> io::Result<()> {
    fs::File::create_new(path)?.write_all(text.as_bytes())
}

fn argument(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
