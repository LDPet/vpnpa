#!/bin/sh
# Download the latest vpnpa release, verify sha256, install it for the
# current user and run `vpnpa install`. A second run updates the binary
# the same way `vpnpa update` does and does not touch the config.
# No root: the files live under $HOME.
set -eu

REPO="LDPet/vpnpa"
BASE="https://github.com/${REPO}/releases/latest/download"

if [ "$(id -u)" -eq 0 ]; then
  echo "vpnpa ставится без root, в домашний каталог пользователя. Запустите скрипт обычным пользователем." >&2
  exit 1
fi

if [ -z "${HOME:-}" ]; then
  echo "HOME не задан" >&2
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

if ! command -v curl >/dev/null 2>&1; then
  echo "нужен curl" >&2
  exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "нужен sha256sum" >&2
  exit 1
fi

# Release bytes are not secret, but a tight umask keeps the partial
# download from being world-readable. The installed binary is chmod 0755.
umask 077

# Remember this before replacing the binary. Restart only if the user
# service was already running; a stopped service must stay stopped.
was_active=0
if command -v systemctl >/dev/null 2>&1; then
  if systemctl --user is-active vpnpa.service >/dev/null 2>&1; then
    was_active=1
  fi
fi

dest_dir="${HOME}/.local/bin"
dest="${dest_dir}/vpnpa"
mkdir -p "$dest_dir"

tmp=$(mktemp -d)
stage=""
cleanup() {
  if [ -n "${tmp:-}" ]; then
    rm -rf "$tmp"
  fi
  if [ -n "${stage:-}" ]; then
    rm -f "$stage"
  fi
}
trap cleanup EXIT

# release_host is the host of an https URL, without userinfo, port or path.
# The glob is applied only to that host so a path containing
# ".githubusercontent.com" cannot widen the allowlist.
release_host() {
  rest=${1#https://}
  rest=${rest%%/*}
  rest=${rest%%\?*}
  rest=${rest##*@}
  printf '%s' "${rest%%:*}"
}

# check_url allows only the GitHub release hosts. Redirects to loopback,
# link-local or any other host are refused before the next request.
check_url() {
  eff=$1
  case "$eff" in
    https://*) ;;
    *)
      echo "неожиданный адрес загрузки" >&2
      return 1
      ;;
  esac
  host=$(release_host "$eff")
  if [ -z "$host" ]; then
    echo "неожиданный адрес загрузки" >&2
    return 1
  fi
  case "$host" in
    github.com|*.githubusercontent.com) return 0 ;;
  esac
  case "$host" in
    *[!A-Za-z0-9._-]*) host="(скрыт)" ;;
  esac
  echo "неожиданный адрес загрузки: ${host}" >&2
  return 1
}

download() {
  url=$1
  out=$2
  n=0
  check_url "$url" || return 1
  while [ "$n" -lt 5 ]; do
    hdr="${out}.hdr"
    code=$(curl -sS --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 0 \
      -A vpnpa -D "$hdr" -o "$out" -w '%{http_code}' "$url") || return 1
    case "$code" in
      200) return 0 ;;
      301|302|303|307|308)
        loc=$(tr -d '\r' < "$hdr" | awk 'tolower(substr($0, 1, 9)) == "location:" { sub(/^[Ll]ocation:[[:space:]]*/, ""); print; exit }')
        if [ -z "$loc" ]; then
          echo "редирект без Location" >&2
          return 1
        fi
        case "$loc" in
          https://*) ;;
          *)
            echo "редирект не на https" >&2
            return 1
            ;;
        esac
        check_url "$loc" || return 1
        url=$loc
        ;;
      *)
        echo "загрузка не удалась: HTTP ${code}" >&2
        return 1
        ;;
    esac
    n=$((n + 1))
  done
  echo "слишком много перенаправлений" >&2
  return 1
}

download "${BASE}/SHA256SUMS" "${tmp}/SHA256SUMS"
download "${BASE}/${asset}" "${tmp}/${asset}"

if [ ! -s "${tmp}/${asset}" ]; then
  echo "пустой файл ${asset}" >&2
  exit 1
fi

# SHA256SUMS lines are "<hash>  <name>" or "<hash> *<name>".
hash=$(awk -v name="$asset" '
  {
    gsub(/\r/, "")
    star = "*" name
    if ($NF == name || $NF == star) { print $1; exit }
  }
' "${tmp}/SHA256SUMS")
if ! printf '%s\n' "$hash" | grep -Eq '^[0-9a-fA-F]{64}$'; then
  echo "в SHA256SUMS нет корректной суммы ${asset}" >&2
  exit 1
fi
printf '%s  %s\n' "$hash" "${tmp}/${asset}" | sha256sum -c --strict -

# Same directory as the destination, then rename. Writing the running
# binary in place returns ETXTBSY. mktemp uses O_EXCL so a symlink planted
# under a predictable name is not followed.
stage=$(mktemp "${dest_dir}/.vpnpa-update.XXXXXX")
cp "${tmp}/${asset}" "$stage"
chmod 0755 "$stage"
if command -v sync >/dev/null 2>&1; then
  sync "$stage" 2>/dev/null || true
fi
mv -f "$stage" "$dest"
stage=""

case ":${PATH}:" in
  *":${dest_dir}:"*) ;;
  *)
    line='export PATH="$HOME/.local/bin:$PATH"'
    if ! grep -Fqs "$line" "${HOME}/.bashrc" 2>/dev/null; then
      printf '\n%s\n' "$line" >> "${HOME}/.bashrc"
      echo "В ~/.bashrc добавлен PATH. Откройте новый терминал, чтобы команда vpnpa нашлась без полного пути."
    else
      echo "Откройте новый терминал: ~/.local/bin ещё нет в PATH этого сеанса."
    fi
    ;;
esac

"$dest" install

if [ "$was_active" -eq 1 ]; then
  systemctl --user restart vpnpa.service
fi
