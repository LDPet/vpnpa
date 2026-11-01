#!/bin/sh
set -eu
version=${1:?version required}
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mkdir -p "$root/installer-build"
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=windows GOARCH="$arch" go build -trimpath -ldflags='-s -w -H windowsgui' -o "$root/installer-build/vpnpa-$arch.exe" "$root/cmd/vpnpa"
  makensis -DBINARY="$root/installer-build/vpnpa-$arch.exe" -DOUTPUT="$root/installer-build/vpnpa-setup-$arch.exe" -DVERSION="$version" "$root/installer/vpnpa.nsi"
done
