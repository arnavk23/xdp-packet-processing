#!/usr/bin/env bash
set -euo pipefail

# omeC_build.sh
# Helper script to clone OMEC UPF v1.5.0 and attempt a build. This script is conservative:
# it only clones and runs the repository's top-level build steps. You should review the
# OMEC README and install dependencies (libdpdk, build tools) before running the built binary.

REPO_URL="https://github.com/omec-project/upf.git"
TAG="v1.5.0"
OUTDIR="$(pwd)/upf-v1.5.0"

if [[ -d "$OUTDIR" ]]; then
  echo "$OUTDIR already exists; remove or rename it first if you want a fresh clone"
  exit 1
fi

echo "Cloning OMEC UPF $TAG to $OUTDIR"
git clone "$REPO_URL" "$OUTDIR"
cd "$OUTDIR"
git fetch --tags --all
git checkout "tags/$TAG" -b "$TAG"

echo "Attempting a build. Follow the repository README for required dependencies."
if [[ -f configure ]]; then
  ./configure || true
fi
if [[ -f Makefile ]]; then
  make -j$(nproc) || true
fi
if [[ -d build ]]; then
  cd build
  if [[ -f CMakeLists.txt ]]; then
    cmake .. || true
    make -j$(nproc) || true
  fi
fi

echo "Build attempt finished. Check $OUTDIR for binaries (bin/, build/, or similar)."
echo "If build failed, install dependencies per the OMEC UPF README and re-run this script."
