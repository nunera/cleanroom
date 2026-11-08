#!/usr/bin/env bash
# "Bring any Debian app": run the command center's .deb, unchanged, inside the admitted Debian root.
#
#   scripts/launch-tui.sh [--no-build] [--socket PATH] [-- cleanroom-tui flags...]
#
# 1. Builds the static musl cleanroom-tui .deb (skip with --no-build).
# 2. Copies the admitted Debian rootfs to store/roots/debian-tui/rootfs (the admitted root is never
#    modified) and installs the .deb into the copy with the root's own dpkg-deb -x.
# 3. Runs /usr/bin/cleanroom-tui in bubblewrap with that copy read-only as /. The only host paths
#    inside are cleanroomd's socket directory (read-only) and the commander key file (read-only);
#    the terminal comes in on stdin/stdout. No host home, no network.
#
# Environment: CLEANROOM_DEBIAN_ROOTFS overrides the admitted rootfs path.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# bubblewrap comes from the dev shell; re-enter through it when it isn't on PATH.
if ! command -v bwrap >/dev/null; then
  exec nix develop "$repo" --command "$0" "$@"
fi

state=${XDG_STATE_HOME:-$HOME/.local/state}/cleanroom
admitted=${CLEANROOM_DEBIAN_ROOTFS:-$state/store/roots/debian/rootfs}
tui_root=$state/store/roots/debian-tui/rootfs
deb=$repo/target/debian/cleanroom-tui_0.1.0-1_amd64.deb
key=$state/keys/commander.key
socket=${XDG_RUNTIME_DIR:+$XDG_RUNTIME_DIR/cleanroom/cleanroomd.sock}
build=1

while (($#)); do
  case $1 in
    --no-build) build=0 ;;
    --socket) socket=${2:?--socket needs a path}; shift ;;
    --) shift; break ;;
    -h | --help) sed -n '2,13s/^# \{0,1\}//p' "$0"; exit 0 ;;
    *) echo "launch-tui: unknown flag $1 (TUI flags go after --)" >&2; exit 2 ;;
  esac
  shift
done
[[ -n $socket ]] || { echo "launch-tui: XDG_RUNTIME_DIR is unset; pass --socket PATH" >&2; exit 2; }

if [[ ! -x $admitted/bin/sh ]]; then
  cat >&2 <<EOF
launch-tui: no admitted Debian root at $admitted
Start cleanroomd once: it admits roots/debian-bookworm.lock.json (fetch by digest, verify, unpack)
into $state/store/roots/debian. scripts/demo.sh does this for you.
EOF
  exit 1
fi

if ((build)); then
  echo "launch-tui: building the cleanroom-tui .deb (static musl)" >&2
  (cd "$repo" && nix develop --command nix shell --inputs-from . \
    nixpkgs#pkgsCross.musl64.buildPackages.rustc nixpkgs#pkgsCross.musl64.stdenv.cc \
    --command env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-cc \
    'CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS=-C target-feature=+crt-static' \
    cargo deb -p cleanroom-tui --target x86_64-unknown-linux-musl) >&2
fi
[[ -f $deb ]] || { echo "launch-tui: $deb is missing; run without --no-build" >&2; exit 1; }

# Unpacked roots can hold read-only directories; make them writable before deleting.
remove_tree() { if [[ -e $1 ]]; then chmod -R u+w "$1" && rm -rf "$1"; fi; }

# Reinstall only when the package or the admitted root changed.
stamp="$(sha256sum <"$deb" | cut -d' ' -f1) $(stat -c '%i %Y' "$admitted")"
if [[ ! -x $tui_root/usr/bin/cleanroom-tui || "$(cat "$tui_root.stamp" 2>/dev/null)" != "$stamp" ]]; then
  echo "launch-tui: installing $(basename "$deb") into a copy of the Debian root" >&2
  remove_tree "$tui_root.new"
  mkdir -p "$(dirname "$tui_root")"
  cp -a --reflink=auto "$admitted" "$tui_root.new"
  bwrap --unshare-all --die-with-parent --new-session --clearenv \
    --bind "$tui_root.new" / --proc /proc --dev /dev --tmpfs /tmp \
    --ro-bind "$deb" /tmp/cleanroom-tui.deb \
    --setenv PATH /usr/sbin:/usr/bin:/sbin:/bin \
    dpkg-deb -x /tmp/cleanroom-tui.deb /
  remove_tree "$tui_root"
  mv "$tui_root.new" "$tui_root"
  printf '%s\n' "$stamp" >"$tui_root.stamp"
fi

# The commander's signing key: a 64-hex Ed25519 seed, created here so it can be bound read-only.
if [[ ! -f $key ]]; then
  (umask 077 && mkdir -p "$(dirname "$key")" &&
    od -An -tx1 -N32 /dev/urandom | tr -d ' \n' >"$key" && echo >>"$key")
  echo "launch-tui: created the commander key $key" >&2
fi

# cleanroomd may still be starting (demo.sh launches everything at once).
for _ in $(seq 60); do [[ -S $socket ]] && break; sleep 0.5; done
[[ -S $socket ]] || { echo "launch-tui: no cleanroomd socket at $socket" >&2; exit 1; }

exec bwrap --unshare-all --die-with-parent --new-session --clearenv \
  --ro-bind "$tui_root" / \
  --proc /proc --dev /dev --tmpfs /tmp --tmpfs /run \
  --ro-bind "$(dirname "$socket")" /run/cleanroom \
  --ro-bind "$key" /tmp/state/cleanroom/keys/commander.key \
  --setenv PATH /usr/bin:/bin \
  --setenv HOME /tmp \
  --setenv LANG C.UTF-8 \
  --setenv TERM "${TERM:-xterm-256color}" \
  --setenv COLORTERM "${COLORTERM:-truecolor}" \
  --setenv XDG_STATE_HOME /tmp/state \
  --setenv XDG_RUNTIME_DIR /run \
  --chdir /tmp \
  /usr/bin/cleanroom-tui --socket "/run/cleanroom/$(basename "$socket")" "$@"
