# PS5 Zstd TOML Generator

PS5 Zstd TOML Generator is a Rust library and command-line tool for generating AMPR Zstd packing profiles from extracted PS5 dumps. The `ps5-pack-analyzer` executable reads the dump locally and writes reports and TOML profiles for PS5 Dump Forge.

**The default profile keeps every file loose.** The separate profile in `candidates/` proposes files for compression based on static evidence and, in full mode, sampled compression savings. Candidates depend on the input dump and require validation on a PS5.

## Windows x64 quick start

1. Open [Releases](https://github.com/giusepper11/ps5-zstd-toml-generator/releases), select the prerelease, and download the `windows-x64` ZIP under **Assets**.
2. Extract the entire ZIP and double-click `Start-Generator.cmd`. The portable version runs without Rust or Git.
3. Paste the path to the extracted dump. Press Enter to accept the suggested output folder or enter a new one. The tool prints both profile paths when it finishes.

If the summary lists candidates, open `candidates/profile.toml` under **Pack → Custom rules (TOML)** in Forge to test compression. Keep any `paths-*.txt` files next to the profile and validate the result on a PS5.

Windows may display a reputation warning because the prerelease is unsigned. Compare the ZIP's SHA-256 with the `.sha256` file from the same prerelease. You can also run the executable directly from PowerShell.

```powershell
.\ps5-pack-analyzer.exe 'D:\My Game' 'D:\My Game-toml'
.\ps5-pack-analyzer.exe --verify 'D:\My Game' 'D:\My Game-toml'
```

## Build from source

Install Rust 1.85 or later and use an extracted dump with UTF-8 paths. The following examples run from the repository root. Choose a new output folder outside the dump with an existing parent folder. Keep the dump unchanged during analysis.

```sh
git clone https://github.com/giusepper11/ps5-zstd-toml-generator.git
cd ps5-zstd-toml-generator
cargo run --release --locked -- ./example-dump ./analysis-output
```

The default `--full` mode inventories the dump, inspects headers and readable executables, and measures compression savings for sample files from candidate families. `--strict` limits candidates to apparent APR resolver arguments. `--manifest-candidates` considers candidates identified in catalogs. `--headers` also scans file headers in either diagnostic mode. Run `--help` for all options.

| Output | Contents |
| --- | --- |
| `profile.toml` | Conservative profile with `default_action = "loose"` |
| `candidates/profile.toml` | Experimental profile with the suggested selection |
| `paths-*.txt` | Optional pattern lists. Keep them next to the profile that references them |
| `selected.txt` | Paths selected by the profile in the same folder |
| `certificate.txt` | Hashes for the inventory, profile, selection, and evidence ranges |
| `report.txt` and `decisions.tsv` | Analysis coverage and the reason for each file decision |

Use `--exploratory` to export the candidates to the main `profile.toml` as well. Forge applies the profile the next time it builds the pack. In the Forge CLI, pass the profile through `--pack-profile`. The analyzer caps its output at 256 MiB and requires an additional 1 GiB of free disk space on Windows.

The selection model follows [PS5 Dump Forge 0.5.4](https://github.com/quer3q/ps5-dump-forge/blob/v0.5.4/docs/packing.md) and [ampr-emu-ng 0.3.2](https://github.com/quer3q/ampr-emu-ng/blob/v0.3.2/docs/zstd-format.md). Check your versions before applying a profile. Test the candidate pack on the console, including a cold boot, save loading, audio, languages, streaming, and any game transitions that matter for your version.

## Verify an analysis

```sh
cargo run --release --locked -- --verify ./example-dump ./analysis-output
cargo run --release --locked -- --verify ./example-dump ./analysis-output/candidates
cargo run --release --locked -- --trace ./trace.tsv ./analysis-output/certificate.txt
```

`--verify` checks the selection and profile against the inventory, then rereads recorded evidence ranges in blocks of up to 4 MiB. By default, the certificate covers the ranges read during analysis. Use `--full-hash` when generating the profile to cover every byte. That option takes longer for larger dumps. The certificate checks integrity. It offers no origin authentication or atomic snapshot guarantee. Generating a certificate requires at least one nonempty evidence range.

`--trace` reads a file from an external recorder and checks the hash of the certificate text. The [TSV schema](trace-schema.md) describes how to record observations. The report covers the scenarios tested and the identity reported by the recorder.

Reports, path lists, traces, and certificates can contain information about the dump. Use synthetic data in public examples.

## Library and development

- `SourceTree` supplies a stable file inventory and supports exact range reads. The CLI uses the `FolderSource` adapter.
- `analyze` and `analyze_with_progress` return an `Analysis` with separate access to the main profile and the candidates.
- `forge::verify_generated` checks the subset of TOML emitted by the generator. With `forge::verify_with_selector`, a host can check the profile using Forge's own selector.
- The [compression economics API and optional Node.js 24 sampler](ECONOMICS.md) document block sampling and its limits.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
node scripts/sample-zstd.mjs --self-test
```

The Rust tests create synthetic inputs. To estimate savings, the generator sends raw blocks to the `ruzstd` compression API. The XML catalog reader limits each element to 128 attributes.

Write code, user-facing text, and documentation in English. See the [contributor guidelines](CONTRIBUTING.md).

## License

[MIT](LICENSE).
