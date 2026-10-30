param([switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not $SkipBuild) { & "$PSScriptRoot/build-windows.ps1" -NoArchive }
    $engine = (Resolve-Path -LiteralPath 'build/RouteBar-windows-x64/sing-box.exe').Path
    $oldEngine = $env:ROUTEBAR_TEST_ENGINE
    try {
        $env:ROUTEBAR_TEST_ENGINE = $engine
        & cargo test -p routebar-v2 --locked
        if ($LASTEXITCODE -ne 0) { throw 'Rust tests failed.' }
    } finally { $env:ROUTEBAR_TEST_ENGINE = $oldEngine }
    & cargo clippy -p routebar-v2 --all-targets --locked -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Clippy failed.' }
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'Formatting check failed.' }
    & rustfmt --check controller/src/windows/cli.rs
    if ($LASTEXITCODE -ne 0) { throw 'Windows CLI formatting check failed.' }
    & python scripts/test-windows-integration.py
    if ($LASTEXITCODE -ne 0) { throw 'Windows integration checks failed.' }
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    $testExe = Join-Path $root 'build\RouteBar-windows-x64\RouteBar.Tests.exe'
    $source = (Resolve-Path -LiteralPath 'windows/RouteBar.cs').Path
    & $compiler /nologo /target:exe /platform:x64 /warnaserror+ "/out:$testExe" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll $source
    if ($LASTEXITCODE -ne 0) { throw 'UI test build failed.' }
    try {
        & $testExe --self-test
        if ($LASTEXITCODE -ne 0) { throw 'UI self-test failed.' }
    } finally { if (Test-Path -LiteralPath $testExe) { Remove-Item -LiteralPath $testExe } }
    & "$PSScriptRoot/test-windows-ui.ps1"
    & git diff --check
    if ($LASTEXITCODE -ne 0) { throw 'Whitespace check failed.' }
    Write-Output 'Windows checks passed. No system VPN was started.'
} finally { Pop-Location }
