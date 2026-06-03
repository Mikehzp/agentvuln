#!/bin/bash
# agentsec publish script
# Build and upload to PyPI.
#
# Usage:
#   ./scripts/publish.sh              # Build + upload to PyPI
#   ./scripts/publish.sh --test       # Build + upload to TestPyPI
#   ./scripts/publish.sh --build-only # Just build, don't upload

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

MODE="${1:---upload}"

echo "==> Cleaning old builds..."
rm -rf dist/ build/ *.egg-info

echo "==> Installing build tools..."
pip install --quiet build twine

echo "==> Building package..."
python -m build

echo ""
echo "Build artifacts:"
ls -lh dist/
echo ""

if [ "$MODE" = "--build-only" ]; then
    echo "✅ Build complete. To upload to PyPI:"
    echo "   twine upload dist/*"
    echo "   (requires PyPI credentials: https://pypi.org/manage/account/token/)"
    exit 0
fi

if [ "$MODE" = "--test" ]; then
    echo "==> Uploading to TestPyPI..."
    twine upload --repository testpypi dist/*
    echo ""
    echo "✅ Uploaded to TestPyPI."
    echo "   Install with: pip install --index-url https://test.pypi.org/simple/ agentsec"
else
    echo "==> Uploading to PyPI..."
    twine upload dist/*
    echo ""
    echo "✅ Published to PyPI!"
    echo "   Install with: pip install agentsec"
fi
