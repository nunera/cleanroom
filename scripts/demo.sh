#!/usr/bin/env bash
# Bring the Cleanroom demo up in one tmux session ("cleanroom") with three windows:
#   daemon  cleanroomd
#   agents  cleanroom-agents run (the Nemotron team)
#   tui     the command center .deb, launched from the admitted Debian root (scripts/launch-tui.sh)
#
#   scripts/demo.sh [--local] [--replay | --record] [--guardrails on|off] [--memory-tiers]
#
#   --local         load ~/.config/cleanroom/local.env for the agents (local Nemotron on Brev;
#                   start deploy/brev/tunnel.sh first)
#   --replay        replay the recorded model answers in recordings/llm, no model network.
#                   Guardrails default to off, as recorded. Follow the recorded beats in order:
#                   t, Enter, A, Enter, d, Enter; then on F2 ask "What happened, and what should
#                   I do first?", "What has Hunter found in the logs?", "Did anyone try to delete
#                   the evidence?" and "@forensics did anything leave acme-fs?"; Esc, F1, a, v
#   --record        record a fresh run into recordings/llm (the old one moves to recordings/llm.old)
#   --guardrails    agent prompt guardrails at start (default on); g in the TUI toggles them live
#   --memory-tiers  evidence pager: large evidence enters agent context as a handle, paged in
#                   on demand (docs/memory-tiers.md)
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

# Everything below needs the dev shell (cargo, bubblewrap, skopeo, umoci, tmux).
if ! command -v bwrap >/dev/null || ! command -v tmux >/dev/null; then
  exec nix develop "$repo" --command "$0" "$@"
fi

session=cleanroom
local_env=${XDG_CONFIG_HOME:-$HOME/.config}/cleanroom/local.env
use_local=0
replay=0
record=0
guardrails=
memory_tiers=

while (($#)); do
  case $1 in
    --local) use_local=1 ;;
    --replay) replay=1 ;;
    --record) record=1 ;;
    --guardrails) guardrails=${2:?--guardrails needs on or off}; shift ;;
    --memory-tiers) memory_tiers=" --memory-tiers" ;;
    -h | --help) sed -n '2,20s/^# \{0,1\}//p' "$0"; exit 0 ;;
    *) echo "demo: unknown flag $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
((replay == 0 || record == 0)) || { echo "demo: --replay and --record don't mix" >&2; exit 2; }
# A replay must run with the guardrails it was recorded with: the recording is guardrails off.
[[ -n $guardrails ]] || { ((replay)) && guardrails=off || guardrails=on; }
[[ $guardrails == on || $guardrails == off ]] || { echo "demo: --guardrails takes on or off" >&2; exit 2; }
((use_local == 0)) || [[ -r $local_env ]] || { echo "demo: --local needs $local_env" >&2; exit 1; }
if tmux has-session -t "$session" 2>/dev/null; then
  echo "demo: already running. Attach: tmux attach -t $session   Stop: tmux kill-session -t $session" >&2
  exit 1
fi

cd "$repo"
echo "demo: building cleanroomd and cleanroom-agents" >&2
cargo build --release -p cleanroom-daemon -p cleanroom-agents --message-format=short
echo "demo: building cleanroom-ransom and the cleanroom-tui .deb (static musl)" >&2
nix shell --inputs-from . \
  nixpkgs#pkgsCross.musl64.buildPackages.rustc nixpkgs#pkgsCross.musl64.stdenv.cc \
  --command env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-cc \
  'CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS=-C target-feature=+crt-static' \
  bash -c 'cargo build --release -p cleanroom-ransom --target x86_64-unknown-linux-musl --message-format=short &&
    cargo deb -p cleanroom-tui --target x86_64-unknown-linux-musl'

# The agents' window loads its model settings itself, so secrets never pass through tmux.
agents="exec target/release/cleanroom-agents run --guardrails $guardrails$memory_tiers"
cache=$(printf %q "$repo/recordings/llm")
((replay == 0)) || agents="export CLEANROOM_LLM_CACHE=replay CLEANROOM_LLM_CACHE_DIR=$cache; $agents"
if ((record)); then
  [[ ! -d $repo/recordings/llm ]] || { rm -rf "$repo/recordings/llm.old"; mv "$repo/recordings/llm" "$repo/recordings/llm.old"; }
  agents="export CLEANROOM_LLM_CACHE=record CLEANROOM_LLM_CACHE_DIR=$cache; $agents"
fi
((use_local == 0)) || agents="set -a; . $(printf %q "$local_env"); set +a; $agents"

# Windows inherit this shell's PATH (dev shell + tmux) even when a tmux server already runs.
window=(-c "$repo" -e "PATH=$PATH")
tmux new-session -d -s "$session" -n daemon -x 200 -y 50 "${window[@]}" target/release/cleanroomd
tmux set-option -t "$session" remain-on-exit on >/dev/null
tmux new-window -d -t "$session" -n agents "${window[@]}" bash -c "$agents"
# Admission is lazy, so admit both roots (waits for the daemon) before launching from Debian; Alpine
# is Forensics' root, admitted here so its first command doesn't wait on a fetch.
tmux new-window -t "$session" -n tui "${window[@]}" bash -c \
  'target/release/cleanroomd admit debian && target/release/cleanroomd admit alpine && exec scripts/launch-tui.sh --no-build'

echo "demo: up. Windows: daemon, agents, tui." >&2
if [[ -n ${TMUX:-} ]]; then
  exec tmux switch-client -t "$session"
elif [[ -t 1 ]]; then
  exec tmux attach -t "$session"
else
  echo "demo: attach with: tmux attach -t $session" >&2
fi
