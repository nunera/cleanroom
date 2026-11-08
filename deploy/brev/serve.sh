#!/usr/bin/env bash
# Serve Nemotron on one Brev GPU (RTX PRO 6000 96 GB) for Cleanroom's local route.
#
# One OpenAI-compatible endpoint (LiteLLM) on 127.0.0.1:8000 routes by model name, so the laptop
# sees the same model ids as the hosted API:
#   nvidia/nemotron-3.5-lightning-30b-a3b  vLLM, NVFP4 weights   (agent tool loops)
#   nvidia/nemotron-3.5-content-safety     vLLM                  (safety layer 1; not served by the hosted API for our key)
#   nvidia/nemotron-3.5-bolt-e4b           llama.cpp, Q4_K_M     (fast local triage)
# Nothing listens on a public interface. Reach it from the laptop with deploy/brev/tunnel.sh.
#
# Usage on the instance:  CLEANROOM_LOCAL_API_KEY=<secret> ./serve.sh
set -euo pipefail

key="${CLEANROOM_LOCAL_API_KEY:?set CLEANROOM_LOCAL_API_KEY to the secret the laptop will send}"
hf_cache="${HF_CACHE:-$HOME/.cache/huggingface}"
mkdir -p "$hf_cache"

run() {
  local name="$1"
  shift
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --restart unless-stopped "$@" >/dev/null
  echo "started $name"
}

# Lightning first: each vLLM process sizes its memory from what is free at startup.
run lightning --gpus all --ipc=host --network host \
  -v "$hf_cache:/root/.cache/huggingface" \
  vllm/vllm-openai:v0.27.1 \
  --model nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-NVFP4 \
  --served-model-name nvidia/nemotron-3.5-lightning-30b-a3b \
  --host 127.0.0.1 --port 8001 \
  --gpu-memory-utilization 0.55 --max-model-len 131072 \
  --moe-backend marlin --kv-cache-dtype fp8 --enable-prefix-caching \
  --mamba-backend flashinfer --mamba-cache-mode align \
  --reasoning-parser nemotron_v3 --tool-call-parser qwen3_coder --enable-auto-tool-choice

until curl -sf http://127.0.0.1:8001/health >/dev/null; do sleep 10; echo "waiting for lightning..."; done

# The Content Safety card pins vLLM <= 0.20.2.
run content-safety --gpus all --ipc=host --network host \
  -v "$hf_cache:/root/.cache/huggingface" \
  vllm/vllm-openai:v0.20.2 \
  --model nvidia/Nemotron-3.5-Content-Safety \
  --served-model-name nvidia/nemotron-3.5-content-safety \
  --host 127.0.0.1 --port 8002 \
  --gpu-memory-utilization 0.20 --max-model-len 16384

run bolt --gpus all --network host \
  -v "$hf_cache:/root/.cache/huggingface" -e LLAMA_CACHE=/root/.cache/huggingface/llama \
  ghcr.io/ggml-org/llama.cpp:server-cuda13-b11459 \
  --hf-repo nvidia/NVIDIA-Nemotron-3.5-Bolt-E4B-4GB --hf-file Nemotron-3.5-Bolt-E4B-Q4_K_M.gguf \
  --alias nvidia/nemotron-3.5-bolt-e4b \
  --host 127.0.0.1 --port 8003 -c 65536 -ngl 999 --jinja

cat >"$HOME/litellm.yaml" <<'EOF'
model_list:
  - model_name: nvidia/nemotron-3.5-lightning-30b-a3b
    litellm_params: { model: openai/nvidia/nemotron-3.5-lightning-30b-a3b, api_base: "http://127.0.0.1:8001/v1", api_key: "os.environ/UPSTREAM_KEY" }
  - model_name: nvidia/nemotron-3.5-content-safety
    litellm_params: { model: openai/nvidia/nemotron-3.5-content-safety, api_base: "http://127.0.0.1:8002/v1", api_key: "os.environ/UPSTREAM_KEY" }
  - model_name: nvidia/nemotron-3.5-bolt-e4b
    litellm_params: { model: openai/nvidia/nemotron-3.5-bolt-e4b, api_base: "http://127.0.0.1:8003/v1", api_key: "os.environ/UPSTREAM_KEY" }
general_settings:
  master_key: "os.environ/LITELLM_MASTER_KEY"
EOF

# Backends listen on loopback only; the proxy is the one place that checks the key.
run router --network host \
  -e LITELLM_MASTER_KEY="$key" -e UPSTREAM_KEY=unused \
  -v "$HOME/litellm.yaml:/app/config.yaml:ro" \
  ghcr.io/berriai/litellm:main-stable \
  --config /app/config.yaml --host 127.0.0.1 --port 8000

echo "endpoint: http://127.0.0.1:8000/v1 (on the instance). Follow logs with: docker logs -f <lightning|content-safety|bolt|router>"
