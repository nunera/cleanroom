#!/usr/bin/env bash
# Forward the Brev instance's local Nemotron endpoint to this laptop's 127.0.0.1:8000.
# Then run the agents with:
#   CLEANROOM_LOCAL_BASE_URL=http://127.0.0.1:8000/v1
#   CLEANROOM_LOCAL_API_KEY=<same secret as serve.sh>
#   CLEANROOM_LOCAL_MODEL=nvidia/nemotron-3.5-lightning-30b-a3b
#   CLEANROOM_LOCAL_SAFETY_MODEL=nvidia/nemotron-3.5-content-safety
# For a fully local run, point NVIDIA_BASE_URL/NVIDIA_API_KEY at the same endpoint and set
# CLEANROOM_MODEL_SCRIBE=nvidia/nemotron-3.5-lightning-30b-a3b (Ultra is hosted-only).
set -euo pipefail
exec brev port-forward "${BREV_INSTANCE:-cleanroom-nemotron}" --port 8000:8000
