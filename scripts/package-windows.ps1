param(
    [Parameter(Mandatory)]
    [ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+$')]
    [string] $Tag,

    [Parameter(Mandatory)]
    [string] $Executable,

    [Parameter(Mandatory)]
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$exe = Get-Item -LiteralPath $Executable
if ($exe.Name -cne 'ps5-pack-analyzer.exe') {
    throw 'Expected ps5-pack-analyzer.exe.'
}
$version = & $exe.FullName --version
if ($LASTEXITCODE -ne 0 -or $version -cne "ps5-pack-analyzer $($Tag.Substring(1))") {
    throw "The executable version does not match $Tag."
}

$name = "ps5-zstd-toml-generator-$Tag-windows-x64.zip"
$directory = New-Item -ItemType Directory -Path $OutputDirectory -Force
$zip = Join-Path $directory.FullName $name
$checksum = "$zip.sha256"
if ((Test-Path -LiteralPath $zip) -or (Test-Path -LiteralPath $checksum)) {
    throw "Package already exists in $($directory.FullName)."
}

$files = @(
    $exe.FullName
    (Join-Path $PSScriptRoot 'windows/Abrir-gerador.cmd')
    (Join-Path $PSScriptRoot 'windows/LEIA-ME.txt')
    (Join-Path $PSScriptRoot '../LICENSE')
)
Compress-Archive -LiteralPath $files -DestinationPath $zip
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText($checksum, "$hash  $name`n", [Text.Encoding]::ASCII)
Write-Output $zip
