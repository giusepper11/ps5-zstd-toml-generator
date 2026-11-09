# Contributor instructions

Follow the [contributor guide](CONTRIBUTING.md). Use English for code, comments, CLI output, documentation, workflows, commits, and pull requests. Use synthetic fixtures for tests and public examples.

## Investigate an unrecognized file

1. Reproduce with a full scan of an extracted dump. Use a new output directory outside the dump.

   ```sh
   cargo run --release --locked -- ./example-dump ./analysis-output --full
   ```

2. Find the file in `decisions.tsv` and read the matching context in `report.txt`. Keep its relative path, size, file family, and decision reason in your local notes. Record the analyzer, Forge, and runtime versions when comparing results.
3. Follow the decision reason before changing any rule.

   | Decision reason | Where to investigate |
   | --- | --- |
   | `unidentified payload` | Inspect `classify` in [src/assets.rs](src/assets.rs). Look for a repeatable signature, version, size, offsets, or companion metadata. |
   | `no linked APR or catalogue evidence` | Check path matching in [src/manifest.rs](src/manifest.rs) and I/O findings in [src/code.rs](src/code.rs) and [src/lib.rs](src/lib.rs). |
   | `missing APR or incomplete executable analysis` or `restricted I/O` | Review executable coverage and read paths in `report.txt`. Keep the existing exclusion when the evidence is incomplete. |
   | `family samples show little savings` or `Frostbite CAS samples show little savings` | Review the samples and threshold in [src/policy.rs](src/policy.rs). Format recognition alone does not qualify a file for compression. |

## Implement a targeted fix

- Check examples from the base game and patch when available. Prefer a format signature with bounds checks or a validated companion file plus a narrowly scoped path. A file extension, title ID, or positive sample alone is insufficient.
- Keep format recognition in `src/assets.rs`, catalogue parsing in `src/manifest.rs`, and compression eligibility in `src/policy.rs`. If recognition depends on another file in the inventory, resolve that relationship in `src/lib.rs`. Reuse `SourceTree` for bounded reads and the existing compression sampler for savings.
- Preserve exclusions for boot, control, media, and restricted I/O. Check for unresolved AIO and mixed container contents. When read compatibility remains uncertain, keep files loose by default and use an explicit test profile if the evidence supports one.
- Follow the existing Frostbite CAS path as an example. The analyzer checks the companion `Data/layout.toc` header and the PS5 superbundle path. It samples each archive, requires at least 8% savings in the sample and APR evidence with complete executable analysis, and adds exact paths only after the user opts in. [Frostbite CLI test](tests/cli.rs)

## Verify the generated profile

- Add a synthetic regression in [tests/profile.rs](tests/profile.rs) or [tests/cli.rs](tests/cli.rs). Include a file that should qualify and a lookalike that should stay loose. Cover a malformed or truncated header when adding a parser.
- Compare `selected.txt` and the TOML rules with the intended paths. Check neighboring files that should stay loose before using a wildcard. Run `--verify` and the checks in [CONTRIBUTING.md](CONTRIBUTING.md#run-the-checks).
- When testing with a real dump, pack to a separate output folder with Forge. On PS5, exercise cold boot, save loading, audio, languages, and transitions that read the changed files. Report the scenarios you actually ran.
