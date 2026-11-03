#!/usr/bin/env bash
# Build a single-file self-audit binary for the CURRENT platform.
# Run this on the OS you want the executable to target:
#   Windows -> build.ps1 (or: bash build.sh under Git Bash/WSL for a Linux bin)
#   Linux   -> bash build.sh   => dist/jwg
#   macOS   -> bash build.sh   => dist/jwg
set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv"
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r requirements.txt pyinstaller

rm -rf build dist
"$VENV/bin/pyinstaller" --clean --noconfirm jwg.spec

echo
echo "built:"
ls -lh dist/
