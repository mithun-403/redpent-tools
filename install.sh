#!/usr/bin/env bash
# redpent-tools tool installer — detects OS/distro and installs the CLI tools the server
# wraps, using the right package manager. Go tools are installed via `go install`.
# Safe to re-run: skips tools already on PATH.
#
# Usage:
#   ./install.sh            # install everything (passive + boundary + active)
#   ./install.sh --passive  # passive + boundary only (no nmap/masscan/nikto)
#   ./install.sh --check     # just report what is / isn't installed
# Note: we deliberately do NOT use `set -e`. One tool failing to install (e.g. a name
# missing from a given package manager) must not abort the whole run — each step warns
# and continues.
set -uo pipefail
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ENV_HINTS=1

LANE="${1:-all}"

# --- OS / package-manager detection ------------------------------------------
OS="$(uname -s)"
PKG=""; SUDO=""
[ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

case "$OS" in
  Darwin) PKG="brew" ;;
  Linux)
    if   command -v apt-get >/dev/null 2>&1; then PKG="apt"
    elif command -v dnf     >/dev/null 2>&1; then PKG="dnf"
    elif command -v pacman  >/dev/null 2>&1; then PKG="pacman"
    elif command -v apk     >/dev/null 2>&1; then PKG="apk"
    else echo "Unsupported Linux: no apt/dnf/pacman/apk found"; exit 1; fi ;;
  *) echo "Unsupported OS '$OS'. On Windows use install.ps1 or the Docker image."; exit 1 ;;
esac
echo "==> OS=$OS  package-manager=$PKG  lane=$LANE"

have() { command -v "$1" >/dev/null 2>&1; }

pkg_install() {
  # pkg_install <common-name> <brew> <apt> <dnf> <pacman> <apk>
  local name="$1" brew="$2" apt="$3" dnf="$4" pac="$5" apk="$6"
  if have "$name"; then echo "  ok   $name (present)"; return; fi
  echo "  +    $name via $PKG"
  case "$PKG" in
    brew)   brew install "$brew" ;;
    apt)    $SUDO apt-get update -qq && $SUDO apt-get install -y "$apt" ;;
    dnf)    $SUDO dnf install -y "$dnf" ;;
    pacman) $SUDO pacman -S --noconfirm "$pac" ;;
    apk)    $SUDO apk add --no-cache "$apk" ;;
  esac || echo "  !!   $name install failed via $PKG (continuing)"
}

go_install() {
  # go_install <binary-name> <module@version>
  # Always installs into GOBIN (idempotent). We do NOT trust `have <name>` here because
  # a same-named binary earlier on PATH (e.g. the Python `httpx` CLI) can shadow the
  # ProjectDiscovery tool; the server resolves Go tools from GOBIN first.
  local name="$1" mod="$2"
  local gobin="${GOBIN:-$HOME/go/bin}"
  if [ -x "$gobin/$name" ]; then echo "  ok   $name (in $gobin)"; return; fi
  if ! have go; then echo "  !!   go not installed; cannot install $name ($mod)"; return; fi
  echo "  +    $name via go install -> $gobin"
  GOBIN="$gobin" go install "$mod"
}

pipx_install() {
  local name="$1" pkg="$2"
  if have "$name"; then echo "  ok   $name (present)"; return; fi
  if have pipx; then echo "  +    $name via pipx"; pipx install "$pkg" || true
  else echo "  +    $name via pip --user"; python3 -m pip install --user "$pkg" || true; fi
}

if [ "$LANE" = "--check" ]; then
  echo "==> Tool status (checks PATH and \$GOBIN/~/go/bin, matching how the server resolves):"
  GOBIN_DIR="${GOBIN:-$HOME/go/bin}"
  for t in whois dig subfinder httpx theHarvester waybackurls nmap masscan ffuf nikto sqlmap commix wafw00f sslscan openssl curl go; do
    printf "  %-14s " "$t"
    if have "$t" || [ -x "$GOBIN_DIR/$t" ]; then echo present; else echo MISSING; fi
  done
  exit 0
fi

echo "==> Python dependencies"
python3 -m pip install -r "$(dirname "$0")/requirements.txt" 2>/dev/null || \
  python3 -m pip install --user -r "$(dirname "$0")/requirements.txt"

echo "==> Passive + boundary CLI tools"
pkg_install whois    whois   whois    whois   whois        whois
pkg_install dig      bind    dnsutils bind-utils bind       bind-tools
pkg_install curl     curl    curl     curl    curl         curl
pkg_install openssl  openssl openssl  openssl openssl      openssl
# wafw00f + theHarvester are Python tools — install via pipx (not in brew).
# NOTE: the PyPI "theHarvester" is a placeholder (v0.0.1); the real tool must come
# from GitHub, which also provides the `theHarvester` console script.
pipx_install wafw00f wafw00f
if ! have theHarvester; then
  echo "  +    theHarvester via pipx (git source)"
  if have pipx; then pipx install "git+https://github.com/laramies/theHarvester.git" || \
    echo "  !!   theHarvester install failed (continuing)"
  else echo "  !!   pipx not found; install pipx then: pipx install git+https://github.com/laramies/theHarvester.git"; fi
else echo "  ok   theHarvester (present)"; fi
pkg_install sslscan  sslscan sslscan  sslscan sslscan      sslscan

go_install subfinder    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go_install httpx         github.com/projectdiscovery/httpx/cmd/httpx@latest
go_install waybackurls   github.com/tomnomnom/waybackurls@latest

if [ "$LANE" = "all" ]; then
  echo "==> Active CLI tools (gated at runtime by scope.yaml)"
  pkg_install nmap    nmap    nmap    nmap    nmap    nmap
  pkg_install masscan masscan masscan masscan masscan masscan
  pkg_install nikto   nikto   nikto   nikto   nikto   nikto
  go_install  ffuf    github.com/ffuf/ffuf/v2@latest
  # Injection tools (Python) — pipx keeps them isolated.
  pipx_install sqlmap sqlmap
  # NOTE: PyPI "commix" is a broken stub (v0.1); install the real tool from GitHub.
  if ! have commix; then
    echo "  +    commix via pipx (git source)"
    have pipx && { pipx install "git+https://github.com/commixproject/commix.git" || \
      echo "  !!   commix install failed (continuing)"; } || \
      echo "  !!   pipx not found; install pipx then: pipx install git+https://github.com/commixproject/commix.git"
  else echo "  ok   commix (present)"; fi
fi

echo
echo "==> Done. If go tools are missing from PATH, add:  export PATH=\"\$PATH:\${GOBIN:-\$HOME/go/bin}\""
echo "==> Verify:  ./install.sh --check"
