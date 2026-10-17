<#
Build KeyVault for Windows.

  .\scripts\build-windows.ps1                 # this PC's architecture
  .\scripts\build-windows.ps1 -Arch x64       # Intel / AMD 64-bit
  .\scripts\build-windows.ps1 -Arch arm64     # Windows on ARM (Snapdragon / Surface Pro X …)

Output in dist\:
  KeyVault-<version>-windows-<arch>.zip         portable: unzip and run KeyVault.exe
  KeyVault-<version>-windows-<arch>-setup.exe   installer (only if Inno Setup 6 is installed)

Needs:
  * Rust: https://rustup.rs (choose the default MSVC toolchain)
  * Visual Studio 2022 Build Tools with "Desktop development with C++"
    (for -Arch arm64 also tick "MSVC ARM64 build tools", and install LLVM/clang:
     winget install LLVM.LLVM)
  * Optional, for the installer: Inno Setup 6 (winget install JRSoftware.InnoSetup)

If PowerShell refuses to run scripts:  powershell -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
#>
param(
    [ValidateSet("x64", "arm64", "")]
    [string]$Arch = ""
)
$ErrorActionPreference = "Stop"

function Say($msg) { Write-Host "==> $msg" -ForegroundColor Magenta }
function Die($msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Die "Rust isn't installed. Get it from https://rustup.rs, then open a new terminal."
}

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Version = "0.1.0"
$inPackage = $false
foreach ($line in Get-Content "Cargo.toml") {
    if ($line -match '^\[workspace\.package\]') { $inPackage = $true; continue }
    if ($inPackage -and $line -match '^\[') { break }
    if ($inPackage -and $line -match '^version\s*=\s*"([^"]+)"') { $Version = $Matches[1]; break }
}

if ($Arch -eq "") {
    $Arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") { "arm64" } else { "x64" }
}
$Target = if ($Arch -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }

if (Get-Command rustup -ErrorAction SilentlyContinue) { rustup target add $Target | Out-Null }

if ($Arch -eq "arm64" -and -not (Get-Command clang -ErrorAction SilentlyContinue)) {
    $llvm = "C:\Program Files\LLVM\bin"
    if (Test-Path "$llvm\clang.exe") { $env:PATH = "$llvm;$env:PATH" }
    else { Die "ARM64 builds need clang (for the TLS library). Install it: winget install LLVM.LLVM" }
}

Say "Building KeyVault $Version for windows-$Arch ($Target, release)..."
cargo build --release --locked -p keyvault-app --target $Target
if ($LASTEXITCODE -ne 0) { Die "cargo build failed" }
$Exe = "target\$Target\release\keyvault.exe"

$Dist = Join-Path $Root "dist"
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

# ── portable zip ───────────────────────────────────────────────────────────
Say "Packing the portable .zip..."
$Stage = Join-Path ([System.IO.Path]::GetTempPath()) ("keyvault-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Stage | Out-Null
Copy-Item $Exe (Join-Path $Stage "KeyVault.exe")
@"
KeyVault $Version for Windows ($Arch)

Run KeyVault.exe. No install needed.
Your vault is stored in %APPDATA%\keyvault\vault.json.

Windows may show "Windows protected your PC" the first time, because this build
isn't code-signed: click "More info" -> "Run anyway".
"@ | Set-Content -Encoding UTF8 (Join-Path $Stage "README.txt")
$Zip = Join-Path $Dist "KeyVault-$Version-windows-$Arch.zip"
if (Test-Path $Zip) { Remove-Item $Zip }
Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $Zip
Remove-Item -Recurse -Force $Stage

# ── installer (Inno Setup) ─────────────────────────────────────────────────
$Iscc = Get-Command iscc -ErrorAction SilentlyContinue
if (-not $Iscc) {
    foreach ($p in @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe")) {
        if ($p -and (Test-Path $p)) { $Iscc = $p; break }
    }
}
$Setup = $null
if ($Iscc) {
    Say "Building the installer..."
    $IssArch = if ($Arch -eq "arm64") { "arm64" } else { "x64compatible" }
    & $Iscc /Q "/DAppVersion=$Version" "/DArch=$Arch" "/DArchAllowed=$IssArch" "/DSourceExe=$Root\$Exe" "/DOutDir=$Dist" "packaging\windows\keyvault.iss"
    if ($LASTEXITCODE -ne 0) { Die "Inno Setup failed" }
    $Setup = Join-Path $Dist "KeyVault-$Version-windows-$Arch-setup.exe"
} else {
    Write-Host "   (Inno Setup not found - skipping the installer; the .zip is ready)"
}

Say "Done."
Write-Host "   $Zip"
if ($Setup) { Write-Host "   $Setup" }
