param([switch]$SkipRustBuild, [switch]$NoArchive)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = Join-Path $root 'build/RouteBar-windows-x64'
$cache = Join-Path $root '.tools/downloads'
$version = '1.14.4'
$archiveName = "sing-box-$version-windows-amd64.zip"
$sha = '99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
if (-not [Environment]::Is64BitOperatingSystem) { throw 'Windows x64 is required.' }
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework 4.8 is required (included in supported Windows 10/11).' }
New-Item -ItemType Directory -Force $output, $cache | Out-Null
Push-Location $root
try {
    if (-not $SkipRustBuild) {
        & cargo build --release -p routebar-v2 --locked --target x86_64-pc-windows-msvc
        if ($LASTEXITCODE -ne 0) { throw 'Rust controller build failed. Install Rust and Visual Studio C++ Build Tools.' }
    }
    Copy-Item -LiteralPath 'target/x86_64-pc-windows-msvc/release/routebar-v2.exe' -Destination $output
    $appExe = Join-Path $output 'RouteBar.exe'
    $manifest = (Resolve-Path -LiteralPath 'windows/app.manifest').Path
    $source = (Resolve-Path -LiteralPath 'windows/RouteBar.cs').Path
    & $compiler /nologo /target:winexe /platform:x64 /optimize+ /warnaserror+ "/out:$appExe" "/win32manifest:$manifest" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll $source
    if ($LASTEXITCODE -ne 0) { throw 'Windows UI build failed.' }
    $archive = Join-Path $cache $archiveName
    if (-not (Test-Path -LiteralPath $archive) -or (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $sha) {
        $download = Join-Path $cache ([Guid]::NewGuid().ToString('N') + '.download')
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/SagerNet/sing-box/releases/download/v$version/$archiveName" -OutFile $download
            if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash -ne $sha) { throw 'Engine archive SHA-256 mismatch.' }
            Move-Item -LiteralPath $download -Destination $archive -Force
        } finally { if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download } }
    }
    $stage = Join-Path $cache ('stage-' + [Guid]::NewGuid().ToString('N'))
    try {
        Expand-Archive -LiteralPath $archive -DestinationPath $stage
        $engineDir = Join-Path $stage "sing-box-$version-windows-amd64"
        Copy-Item -LiteralPath (Join-Path $engineDir 'sing-box.exe') -Destination $output
        # Upstream also ships libcronet.dll. Copy all DLLs alongside the engine.
        Get-ChildItem -LiteralPath $engineDir -Filter '*.dll' | Copy-Item -Destination $output
        $licenses = Join-Path $output 'Licenses'
        New-Item -ItemType Directory -Force $licenses | Out-Null
        Copy-Item -LiteralPath (Join-Path $engineDir 'LICENSE') -Destination (Join-Path $licenses 'sing-box-LICENSE')
        Copy-Item -LiteralPath 'LICENSE' -Destination (Join-Path $licenses 'RouteBar-LICENSE')
        Copy-Item -LiteralPath 'THIRD_PARTY_NOTICES.md' -Destination $licenses
        Copy-Item -LiteralPath 'docs/WINDOWS.md' -Destination (Join-Path $output 'README.md')
        Copy-Item -LiteralPath 'windows/config.example.yaml' -Destination (Join-Path $output 'config.example.yaml')
    } finally {
        # Only this invocation's staging directory, resolved inside the download cache.
        if (Test-Path -LiteralPath $stage) {
            $resolved = (Resolve-Path -LiteralPath $stage).Path
            $cacheRoot = (Resolve-Path -LiteralPath $cache).Path.TrimEnd('\') + '\'
            if (-not $resolved.StartsWith($cacheRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe staging path.' }
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
    & (Join-Path $output 'sing-box.exe') version
    if ($LASTEXITCODE -ne 0) { throw 'Bundled engine did not run.' }
    if (-not $NoArchive) { Compress-Archive -Path "$output/*" -DestinationPath (Join-Path $root 'build/RouteBar-windows-x64.zip') -Force }
    Write-Output "Built $output/RouteBar.exe"
} finally { Pop-Location }
