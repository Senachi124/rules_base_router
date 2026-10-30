param([string]$AppDirectory)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $AppDirectory) { $AppDirectory = Join-Path $root 'build/RouteBar-windows-x64' }
$controller = (Resolve-Path -LiteralPath (Join-Path $AppDirectory 'routebar-v2.exe')).Path
$compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
$runDirectory = Join-Path $root ('build/ui-regression-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runDirectory | Out-Null
$testExe = Join-Path $runDirectory 'RouteBar.UiRegressionTests.exe'
$source = (Resolve-Path -LiteralPath (Join-Path $root 'windows/RouteBar.cs')).Path
$tests = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'test-windows-ui.cs')).Path
& $compiler /nologo /target:exe /platform:x64 /warnaserror+ /main:RouteBar.Windows.UiRegressionTests "/out:$testExe" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll $source $tests
if ($LASTEXITCODE -ne 0) { throw 'Windows UI regression build failed.' }
& $testExe $controller
if ($LASTEXITCODE -ne 0) { throw 'Windows UI regression tests failed.' }
