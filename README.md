# PS5 Zstd TOML Generator

Generate a custom Zstd compression profile from an extracted PS5 game folder. The generator finds files worth testing, and PS5 Dump Forge uses the profile to build the pack.

## 🎮 Quick start on Windows x64

1. Download the `windows-x64` ZIP under **Assets** on the prerelease page. [Releases](https://github.com/giusepper11/ps5-zstd-toml-generator/releases)
2. Extract the ZIP and double-click `Start-Generator.cmd`. The portable build runs without Rust or Git.
3. Paste your dump folder path and press Enter to use the suggested output folder. If the wizard offers to include Frostbite archives for testing, press `Y` to include them or Enter to leave them loose.
4. In Forge, open **Pack → Custom rules (TOML)** and select `profile.toml`. Keep any `paths-*.txt` files beside it. Build a Zstd pack and test it on your PS5.

Windows may show a warning for the unsigned executable. You can check the download against the `.sha256` file on the release page.

## 📂 What you get

- **`profile.toml`** lists the files to try compressing. Forge leaves the other files loose.
- **`report.txt` and `decisions.tsv`** explain what was selected or skipped. If nothing qualifies, start with these reports.

## 🛠️ Contribute

Found a file the generator skipped? Share a short, sanitized report with the version and the reason shown in `decisions.tsv`. [Open an issue](https://github.com/giusepper11/ps5-zstd-toml-generator/issues/new)

The [contributor guide](CONTRIBUTING.md) covers PowerShell, building from source, and submitting a fix. See [AGENTS.md](AGENTS.md) for the format investigation workflow.

[MIT License](LICENSE)
