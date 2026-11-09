PS5 Zstd TOML Generator for Windows x64

1. Extract all files from the ZIP into the same folder.
2. Double-click Start-Generator.cmd.
3. Paste the path to your extracted dump and press Enter. Accept the
   suggested output folder or enter a new folder outside the dump.

The main profile keeps all files loose. If the summary lists candidates,
open candidates/profile.toml under Pack > Custom rules (TOML) in PS5 Dump
Forge to test compression. Keep any paths-*.txt files next to the profile
and validate the result on a PS5.

You can also run the executable from PowerShell.
  .\ps5-pack-analyzer.exe 'D:\My Game' 'D:\My Game-toml'
  .\ps5-pack-analyzer.exe --help

Windows may display a reputation warning because this prerelease is
unsigned. Before extracting, compare the ZIP's SHA-256 with the .sha256
file from the same prerelease.

https://github.com/giusepper11/ps5-zstd-toml-generator/releases
