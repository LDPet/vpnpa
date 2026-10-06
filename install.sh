#!/bin/sh
# Download the latest vpnpa release, verify sha256, install it for the
# current user and run `vpnpa install`. A second run updates the binary
# the same way `vpnpa update` does and does not touch the config.
set -eu

REPO="LDPet/vpnpa"
BASE="https://github.com/${REPO}/releases/latest/download"

if ! command -v curl >/dev/null 2>&1; then
  echo "нужен curl" >&2
  exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "нужен sha256sum" >&2
  exit 1
fi

os=$(uname -s)
arch=$(uname -m)
if [ "$os" != "Linux" ]; then
  echo "неподдерживаемая ОС: $os" >&2
  exit 1
fi
case "$arch" in
  x86_64|amd64) asset="vpnpa-linux-amd64" ;;
  aarch64|arm64) asset="vpnpa-linux-arm64" ;;
  *)
    echo "неподдерживаемая архитектура: $arch" >&2
    exit 1
    ;;
esac

dest_dir="${HOME}/.local/bin"
dest="${dest_dir}/vpnpa"
mkdir -p "$dest_dir"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -A vpnpa -o "${tmp}/SHA256SUMS" "${BASE}/SHA256SUMS"
curl -fsSL -A vpnpa -o "${tmp}/${asset}" "${BASE}/${asset}"

# SHA256SUMS lines are "<hash>  <name>" or "<hash> <name>".
hash=$(awk -v name="$asset" '$NF == name { print $1; exit }' "${tmp}/SHA256SUMS")
if [ -z "$hash" ]; then
  echo "в SHA256SUMS нет ${asset}" >&2
  exit 1
fi
echo "${hash}  ${tmp}/${asset}" | sha256sum -c -

# Same directory as the destination, then rename. Writing the running
# binary in place returns ETXTBSY.
stage="${dest_dir}/.vpnpa-update.$$"
cp "${tmp}/${asset}" "$stage"
chmod 0755 "$stage"
mv -f "$stage" "$dest"

case ":${PATH}:" in
  *":${dest_dir}:"*) ;;
  *)
    line='export PATH="$HOME/.local/bin:$PATH"'
    if ! grep -Fqs "$line" "${HOME}/.bashrc" 2>/dev/null; then
      printf '\n%s\n' "$line" >> "${HOME}/.bashrc"
    fi
    echo "В ~/.bashrc добавлен PATH. Откройте новый терминал, чтобы команда vpnpa нашлась без полного пути."
    ;;
esac

if command -v systemctl >/dev/null 2>&1; then
  if systemctl --user is-active vpnpa.service >/dev/null 2>&1; then
    systemctl --user restart vpnpa.service || true
  fi
fi

exec "$dest" install
