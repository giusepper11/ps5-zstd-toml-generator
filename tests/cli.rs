use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

mod common;
use common::synthetic_elf;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ps5-analyzer-cli-{}-{unique}", std::process::id()));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Only remove the uniquely created fixture directory.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ps5-pack-analyzer"))
        .args(args)
        .output()
        .unwrap()
}

fn successful(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn guided(input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ps5-pack-analyzer"))
        .arg("--interactive")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn guided_mode_accepts_quoted_paths_and_checks_destinations() {
    let fixture = Fixture::new();
    let dump = fixture.0.join("Café Demo");
    fs::create_dir(&dump).unwrap();
    fs::write(dump.join("eboot.bin"), b"synthetic fixture").unwrap();

    let cancelled = guided(&format!("\"{}\"\n", dump.display()));
    successful(&cancelled);
    assert!(String::from_utf8_lossy(&cancelled.stdout).contains("Analysis canceled"));
    let first = fixture.0.join("Café Demo-toml");
    assert!(!first.exists());

    let output = guided(&format!(
        "\"{}\"\n\"{}\"\n\"{}\"\n\n",
        fixture.0.join("missing").display(),
        dump.display(),
        dump.join("inside").display(),
    ));
    successful(&output);
    let summary = String::from_utf8(output.stdout).unwrap();
    assert!(summary.contains("Invalid dump folder"));
    assert!(summary.contains("output must be outside the dump"));
    assert!(summary.contains("No compression candidates were found"));
    let shown = Path::new(
        summary
            .lines()
            .find_map(|line| line.strip_prefix("Analysis report: "))
            .expect("the summary should show the report path"),
    );
    assert!(shown.is_absolute(), "{shown:?} should be an absolute path");
    assert_eq!(
        shown.canonicalize().unwrap(),
        first.join("report.txt").canonicalize().unwrap()
    );
    assert!(!dump.join("inside").exists());
    assert!(first.join("decisions.tsv").is_file());
    assert_eq!(fs::read_dir(&first).unwrap().count(), 2);

    let occupied = fixture.0.join("occupied");
    fs::create_dir(&occupied).unwrap();
    let output = guided(&format!("{}\n{}\n\n", dump.display(), occupied.display()));
    successful(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("output directory already exists"));
    assert!(fixture.0.join("Café Demo-toml-2/report.txt").is_file());
    assert_eq!(fs::read_dir(&occupied).unwrap().count(), 0);
}

#[test]
fn version_matches_the_cargo_package() {
    let output = run(&[Path::new("--version")]);
    successful(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        concat!("ps5-pack-analyzer ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn full_hash_cli_binds_dump_and_protects_output_locations() {
    let fixture = Fixture::new();
    let dump = fixture.0.join("dump");
    let output = fixture.0.join("output");
    fs::create_dir(&dump).unwrap();
    fs::create_dir(dump.join("sce_sys")).unwrap();
    fs::create_dir(dump.join("data")).unwrap();
    fs::write(dump.join("eboot.bin"), synthetic_elf(false)).unwrap();
    fs::write(
        dump.join("sce_sys/param.json"),
        b"{\"titleId\":\"PPSA00000\"}",
    )
    .unwrap();
    fs::write(dump.join("data/a[0].odxb"), vec![0; 16_384]).unwrap();
    let unselected = dump.join("data/unselected.bin");
    fs::write(&unselected, vec![0x42; 256]).unwrap();

    let generated = run(&[&dump, &output, Path::new("--full-hash")]);
    successful(&generated);
    assert!(String::from_utf8_lossy(&generated.stdout).contains("validate the result on a PS5"));
    assert_eq!(
        fs::read_to_string(output.join("selected.txt")).unwrap(),
        "data/a[0].odxb\n"
    );
    let profile = fs::read_to_string(output.join("profile.toml")).unwrap();
    assert!(profile.contains("action = \"compress\""));
    assert!(profile.contains("data/a[[]0].odxb"));
    assert!(!output.join("candidates").exists());
    successful(&run(&[Path::new("--verify"), &dump, &output]));

    assert!(!run(&[&dump, &output]).status.success());
    let inside = dump.join("forbidden-output");
    assert!(!run(&[&dump, &inside]).status.success());
    assert!(!inside.exists());

    // Alter a byte beyond the header, leaving the file size unchanged. The
    // full-hash certificate must reject it, independently of timestamp checks.
    let mut changed = fs::read(&unselected).unwrap();
    changed[100] ^= 1;
    fs::write(&unselected, changed).unwrap();
    assert!(!run(&[Path::new("--verify"), &dump, &output])
        .status
        .success());
}
