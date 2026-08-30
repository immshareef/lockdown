# Build script for Lockdown
# Run this in PowerShell to build the project

$vsPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Launch-VsDevShell.ps1"

if (Test-Path $vsPath) {
    & $vsPath -Arch amd64 -HostArch amd64
    cargo build --release
    Write-Host "Build complete: target\release\lockdown.exe"
} else {
    Write-Host "Visual Studio Build Tools not found. Please install with:"
    Write-Host "winget install Microsoft.VisualStudio.2022.BuildTools --override '--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'"
}
