use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let dump = fixture.0.join("Jogo de ação");
    fs::create_dir(&dump).unwrap();
    fs::write(dump.join("eboot.bin"), b"synthetic fixture").unwrap();

    let cancelled = guided(&format!("\"{}\"\n", dump.display()));
    successful(&cancelled);
    assert!(String::from_utf8_lossy(&cancelled.stdout).contains("Análise cancelada"));
    let first = fixture.0.join("Jogo de ação-toml");
    assert!(!first.exists());

    let output = guided(&format!(
        "\"{}\"\n\"{}\"\n\"{}\"\n\n",
        fixture.0.join("missing").display(),
        dump.display(),
        dump.join("inside").display(),
    ));
    successful(&output);
    let summary = String::from_utf8(output.stdout).unwrap();
    assert!(summary.contains("Pasta do dump inválida"));
    assert!(summary.contains("output must be outside the dump"));
    assert!(summary.contains("0 candidatos"));
    for (label, expected) in [
        (
            "Perfil conservador (todos os arquivos soltos): ",
            first.join("profile.toml"),
        ),
        (
            "Perfil experimental (0 candidatos): ",
            first.join("candidates/profile.toml"),
        ),
    ] {
        let shown = Path::new(
            summary
                .lines()
                .find_map(|line| line.strip_prefix(label))
                .expect("the summary should show the profile path"),
        );
        assert!(shown.is_absolute(), "{shown:?} should be an absolute path");
        assert_eq!(
            shown.canonicalize().unwrap(),
            expected.canonicalize().unwrap()
        );
    }
    assert!(!dump.join("inside").exists());
    assert!(fs::read_to_string(first.join("selected.txt"))
        .unwrap()
        .is_empty());
    successful(&run(&[Path::new("--verify"), &dump, &first]));

    let occupied = fixture.0.join("occupied");
    fs::create_dir(&occupied).unwrap();
    let output = guided(&format!("{}\n{}\n\n", dump.display(), occupied.display()));
    successful(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("output directory already exists"));
    assert!(fixture.0.join("Jogo de ação-toml-2/profile.toml").is_file());
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
    fs::write(dump.join("eboot.bin"), b"not a readable executable").unwrap();
    fs::write(
        dump.join("sce_sys/param.json"),
        b"{\"titleId\":\"PPSA00000\"}",
    )
    .unwrap();
    let asset = dump.join("data/asset.bin");
    fs::write(&asset, vec![0x42; 256]).unwrap();

    successful(&run(&[&dump, &output, Path::new("--full-hash")]));
    assert!(fs::read_to_string(output.join("selected.txt"))
        .unwrap()
        .is_empty());
    assert!(fs::read_to_string(output.join("profile.toml"))
        .unwrap()
        .contains("default_action = \"loose\""));
    assert!(output.join("candidates/profile.toml").is_file());
    assert!(output.join("candidates/certificate.txt").is_file());
    successful(&run(&[Path::new("--verify"), &dump, &output]));
    successful(&run(&[
        Path::new("--verify"),
        &dump,
        &output.join("candidates"),
    ]));

    assert!(!run(&[&dump, &output]).status.success());
    let inside = dump.join("forbidden-output");
    assert!(!run(&[&dump, &inside]).status.success());
    assert!(!inside.exists());

    // Alter a byte beyond the header, leaving the file size unchanged. The
    // full-hash certificate must reject it, independently of timestamp checks.
    let mut changed = fs::read(&asset).unwrap();
    changed[100] ^= 1;
    fs::write(&asset, changed).unwrap();
    assert!(!run(&[Path::new("--verify"), &dump, &output])
        .status
        .success());
}
