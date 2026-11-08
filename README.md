# Cleanroom

When an attacker owns your network, the first thing you can't trust is your own tools.

Cleanroom is a responder OS for cyber incidents. Every tool, Linux root and agent environment is declared, pinned by digest and admitted by signature before it runs. Nemotron agents investigate inside sandboxed strata, each with only the access its role needs, and a ratatui command center shows the incident, the scope of compromised data and the legal notification clocks as they unfold.

Built at HackUTD 2026 (ZeroDay) for the NVIDIA and Winstead tracks.

## Status

The shared wire contract (`crates/proto`, [docs/interfaces.md](docs/interfaces.md)), the Nemotron agent team (`crates/agents`) and the command center (`crates/tui`) are in place. The daemon `cleanroomd` (strata, grants, receipts, bus server, scenarios) is in progress.

## Layout

| Path | What |
| --- | --- |
| `crates/proto` | Wire types shared by the daemon, agents and TUI |
| `crates/agents` | `cleanroom-agents`: the Nemotron agent team runner (model router, roles, safety and sensitivity layers) |
| `crates/tui` | `cleanroom-tui`: the ratatui incident command center, shipped as a static `.deb` |
| `docs/interfaces.md` | Transport, signing, receipts, daemon operations, grants |
| `docs/concept.md` | What we're building and why |
| `docs/research/` | Research notes behind the design |

## Develop

```sh
nix develop
cargo check
```

## Model access

Nemotron credentials live outside the repo in `~/.config/cleanroom/nemotron.env` (mode `0600`):

```sh
NVIDIA_API_KEY=nvapi-...
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
```

Point `NVIDIA_BASE_URL` at a self-hosted OpenAI-compatible server (Brev, vLLM, NIM) to run Nemotron locally.

## Agents

`cleanroom-agents` connects to `cleanroomd` with one socket connection per role (Hunter, Forensics, Scribe, Containment), waits for an `investigate` bus event, and runs the team: Hunter and Forensics investigate concurrently inside their strata, their findings flow to Scribe, which keeps the incident and scope records, and Containment proposes actions for the commander to approve.

```sh
cleanroom-agents run [--guardrails on|off] [--max-steps N] [--socket PATH] [--once]
```

- `--guardrails` picks the hardened or the naive prompts at start; `agent_control` bus events switch them at runtime. With guardrails off, Hunter and Forensics also get a shell (`exec`), so the demo can show the stratum grant denying what the model was talked into.
- Every evidence-bearing tool output is scored by the Nemotron safety model (`safety_verdict`) before a model sees it; with guardrails on, unsafe output is wrapped in an untrusted-data envelope. Output with personal data or credentials moves the conversation to the local endpoint (`route`).
- Counters arrive as `status` lines containing `blocked_by_model=N blocked_by_os=N safety_flags=N guardrails=on|off llm=live|record|replay`.
- Signing keys are created on first run in `$XDG_STATE_HOME/cleanroom/keys/<role>.key` (mode `0600`).

| Variable | Meaning |
| --- | --- |
| `CLEANROOM_MODEL_HUNTER`, `_FORENSICS`, `_CONTAINMENT` | Tool-loop model (default `nvidia/nemotron-3.5-lightning-30b-a3b`) |
| `CLEANROOM_MODEL_SCRIBE` | Record keeper model (default `nvidia/nemotron-3-ultra-550b-a55b`) |
| `CLEANROOM_MODEL_SAFETY` | Safety model (default `nvidia/llama-3.1-nemotron-safety-guard-8b-v3`) |
| `CLEANROOM_LOCAL_BASE_URL`, `CLEANROOM_LOCAL_MODEL`, `CLEANROOM_LOCAL_API_KEY`, `CLEANROOM_LOCAL_SAFETY_MODEL` | Optional local endpoint for sensitive evidence (model default `nvidia/nemotron-3.5-bolt-e4b`) |
| `CLEANROOM_LLM_CACHE=record\|replay`, `CLEANROOM_LLM_CACHE_DIR` | Record model responses, or replay them without network (default dir `~/.cache/cleanroom/llm`). Replay is labelled in every `status` |
| `CLEANROOM_NIXPKGS` | Pinned flake prefix for tool requests (default: the `flake.lock` nixpkgs rev) |

## Command center

`cleanroom-tui` connects as the commander and renders only from bus events: incident header and legal notification clocks, scope of compromised data, live agent trace, approvals, timeline and comms.

Keys: `d` detonate, `t` tamper then admit, `a`/`x` approve/deny the selected item, `g` toggle agent prompt guardrails, `i` investigate, `v` verify the receipt log, `r` reset, `c` chat, `?` help, `q` quit.

Flags: `--socket PATH`, `--record FILE` (save live events), `--replay FILE [--speed X]` (offline playback with a REPLAY badge; the demo fallback), `--tamper-root NAME` (default `debian`), `--scenario NAME` (default `ransomware`).

Debian package (static musl, runs on bookworm and trixie):

```sh
nix develop --command nix shell --inputs-from . nixpkgs#pkgsCross.musl64.buildPackages.rustc nixpkgs#pkgsCross.musl64.stdenv.cc --command env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-cc 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS=-C target-feature=+crt-static' cargo deb -p cleanroom-tui --target x86_64-unknown-linux-musl
```

## Prior work

Cleanroom rebuilds ideas from [MisaOS](https://github.com/nunera/misaos) (strict records, signed local admission of digest-pinned roots, sandboxed foreign roots, Nix packaging). The Cleanroom code itself is written at the event.

## License

Apache-2.0
