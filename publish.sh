#!/usr/bin/env bash
#
# publish.sh — build, validate, and (optionally) publish the qovaris package.
#
# SAFE BY DEFAULT: with no flags this only builds the wheel/sdist and runs
# `twine check`. It never uploads anything unless you explicitly pass an
# upload flag.
#
# Usage:
#   ./publish.sh                  Build + validate only (no upload).        [default]
#   ./publish.sh --test           Build + validate + upload to TestPyPI.
#   ./publish.sh --production      Build + validate + upload to real PyPI (asks first).
#
# Auth: twine reads credentials from ~/.pypirc or the environment
#   TWINE_USERNAME=__token__  TWINE_PASSWORD=pypi-<your-api-token>
#
set -euo pipefail

# Always operate from the SDK directory (where pyproject.toml lives).
cd "$(dirname "$0")"

TARGET="none"
for arg in "$@"; do
  case "$arg" in
    --test)        TARGET="testpypi" ;;
    --production)  TARGET="pypi" ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *)
      echo "Unknown argument: $arg (try --help)" >&2
      exit 2 ;;
  esac
done

# Prefer `uv run` if available so we don't depend on a pre-activated venv.
# `--no-project` keeps the build isolated from this project's runtime deps —
# `python -m build` builds the backend in its own isolated env regardless, so we
# never need to install qovaris's extras (which require Python >= 3.10) just
# to produce the artifacts.
if command -v uv >/dev/null 2>&1; then
  PY="uv run --no-project --with build python"
  TWINE="uv run --no-project --with twine twine"
else
  PY="python"
  TWINE="twine"
fi

NAME=$(grep -E '^name *= *' pyproject.toml | head -1 | sed -E 's/.*"(.*)".*/\1/')
VERSION=$(grep -E '^version *= *' pyproject.toml | head -1 | sed -E 's/.*"(.*)".*/\1/')

echo "==> Package : ${NAME} ${VERSION}"
echo "==> Target  : ${TARGET}"
echo

echo "==> Cleaning previous build artifacts"
rm -rf dist build ./*.egg-info

echo "==> Building sdist + wheel"
$PY -m build

echo "==> Validating with twine check"
$TWINE check dist/*

if [ "$TARGET" = "none" ]; then
  echo
  echo "✅ Build + validation complete. Artifacts in ./dist/ — nothing uploaded."
  echo "   To publish:  ./publish.sh --test   (TestPyPI)"
  echo "                ./publish.sh --production   (real PyPI)"
  exit 0
fi

# Guard the real PyPI upload behind an interactive confirmation.
if [ "$TARGET" = "pypi" ]; then
  echo
  echo "⚠️  About to upload ${NAME} ${VERSION} to PRODUCTION PyPI."
  echo "    This is PERMANENT — a version can never be re-uploaded once released."
  read -r -p "    Type the version (${VERSION}) to confirm: " CONFIRM
  if [ "$CONFIRM" != "$VERSION" ]; then
    echo "Aborted — confirmation did not match." >&2
    exit 1
  fi
  echo "==> Uploading to PyPI"
  $TWINE upload dist/*
else
  echo "==> Uploading to TestPyPI"
  $TWINE upload --repository testpypi dist/*
  echo
  echo "Smoke-test the upload with:"
  echo "  pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ ${NAME}"
fi

echo "✅ Done."
