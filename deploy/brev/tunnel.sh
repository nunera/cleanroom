#!/usr/bin/env bash
# Forward the Brev instance's local Nemotron endpoint to this laptop's 127.0.0.1:8000, reconnecting if
# the connection drops. Uses the SSH config the Brev CLI writes (~/.brev/ssh_config), so it keeps working
# after the short-lived Brev CLI login expires.
# Then run the agents with:
#   set -a; . ~/.config/cleanroom/local.env; set +a
# For a fully local run, point NVIDIA_BASE_URL/NVIDIA_API_KEY at the same endpoint and set
# CLEANROOM_MODEL_SCRIBE=nvidia/nemotron-3.5-lightning-30b-a3b (Ultra is hosted-only).
set -uo pipefail
host="${BREV_INSTANCE:-cleanroom-nemotron}"
while true; do
  ssh -F "$HOME/.brev/ssh_config" -o BatchMode=yes -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -N -L 127.0.0.1:8000:127.0.0.1:8000 "$host"
  echo "tunnel to $host dropped (exit $?); reconnecting in 3 s" >&2
  sleep 3
done
