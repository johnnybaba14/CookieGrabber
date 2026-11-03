# Build a single-file Windows .exe for the JohnWickGrabber self-audit CLI.
# Run in PowerShell ON WINDOWS (PyInstaller does not cross-compile).
#   Output: dist\jwg.exe
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$Venv = ".venv"
if (-not (Test-Path $Venv)) {
    py -m venv $Venv
}
& "$Venv\Scripts\python.exe" -m pip install --upgrade pip
& "$Venv\Scripts\python.exe" -m pip install -r requirements.txt pyinstaller

if (Test-Path build) { Remove-Item -Recurse -Force build }
if (Test-Path dist)  { Remove-Item -Recurse -Force dist }

& "$Venv\Scripts\pyinstaller.exe" --clean --noconfirm jwg.spec

Write-Host "`nbuilt:"
Get-ChildItem dist | Format-Table Name, Length
