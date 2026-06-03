#!/bin/bash
# agentsec PyPI upload helper
# Usage: ./scripts/upload_pypi.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

echo "==> PyPI upload (token paste mode)"
echo "    Paste your PyPI API token below, then press Enter:"
echo "    (Right-click to paste in WSL terminal)"
echo ""
read -r -s TOKEN

echo "==> Uploading to PyPI..."
TWINE_USERNAME="__token__" TWINE_PASSWORD="$TOKEN" twine upload dist/*

echo ""
echo "✅ Done! Try: pip install agentsec"
