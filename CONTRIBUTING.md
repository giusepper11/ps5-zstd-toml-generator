# Contributing

If a file you expected to compress stayed loose, find its entry in `decisions.tsv` and check `report.txt`. A report is useful even when the generator produces no TOML.

## Report a problem

Include the generator version, the Forge and PS5 runtime versions if used, the analysis mode, the relevant decision reason, and what happened when you tested the pack. A sanitized excerpt or a minimal synthetic reproduction is enough to start. Keep game files, executables, and raw dump reports, traces, and certificates private. [Open an issue](https://github.com/giusepper11/ps5-zstd-toml-generator/issues/new)

## Build and run

Install Rust 1.85.1 to match CI. Run these commands from the repository root with an extracted dump and a new output directory outside it.

```sh
cargo run --release --locked -- ./example-dump ./analysis-output
cargo run --release --locked -- --verify ./example-dump ./analysis-output
```

On Windows, the portable executable takes the same arguments.

```powershell
.\ps5-pack-analyzer.exe 'D:\My Game' 'D:\My Game-toml'
.\ps5-pack-analyzer.exe --verify 'D:\My Game' 'D:\My Game-toml'
```

Full mode runs by default. Use `--help` for diagnostic modes and `--frostbite-cas-candidates` to opt into the same CAS test selection offered by the wizard. To pack from the Forge CLI, pass `--zstd-pack --pack-profile <path-to-profile.toml>` with your conversion command. [PS5 Dump Forge](https://github.com/quer3q/ps5-dump-forge)

## Check an analysis

When the generator exports a profile, `selected.txt` lists its exact selection and `certificate.txt` records the evidence hashes. `--verify` checks them against the dump and re-reads the recorded ranges. Use `--full-hash` during generation to include every input byte in that check. For older outputs, point `--verify` at the directory that holds `profile.toml`.

The verifier checks file integrity. Test a built pack on the PS5 to evaluate gameplay. For external I/O observations and compression measurements, see the [trace schema](trace-schema.md) and [compression economics notes](ECONOMICS.md).

## Submit a change

Use English in code, documentation, CLI text, and pull requests. Keep the change focused and use synthetic test data. Keep Unicode paths in fixtures that test filename handling.

Follow [AGENTS.md](AGENTS.md) for format and selection changes. In your pull request, describe which files the analyzer should pick or leave loose, why, and how you verified that behavior.

### Run the checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --release --locked
node scripts/sample-zstd.mjs --self-test
```

The sampler self-test uses Node.js 24. CI runs the checks on Windows and Linux.
