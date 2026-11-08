# Cleanroom

When an attacker owns your network, the first thing you can't trust is your own tools.

Cleanroom is a responder OS for cyber incidents. Every tool, Linux root and agent environment is declared, pinned by digest and admitted by signature before it runs. Nemotron agents investigate inside sandboxed strata, each with only the access its role needs, and a ratatui command center shows the incident, the scope of compromised data and the legal notification clocks as they unfold.

Built at HackUTD 2026 (ZeroDay) for the NVIDIA and Winstead tracks.

## Status

The full demo runs end to end on one Linux laptop:
- **Admission:** the Debian root is admitted by digest. A tampered byte is rejected, naming the layer, and the clean copy is re-admitted.
- **Detonation:** the canary ransomware locks the `acme-fs` share inside a sandbox, and the scope table turns red.
- **Investigation:** Nemotron agents investigate inside bubblewrap strata.
- **Injection:** with prompt guardrails off, the ransom note's injection talks Hunter and Forensics into `rm -rf /evidence/*`, and the kernel grant denies it, with a signed receipt.
- **Records:** Scribe fills the incident record, scope and legal clocks. The receipt log verifies offline.

Models run on the hosted NVIDIA API or on self-hosted Nemotron on Brev (`deploy/brev/`). Measured results are in [docs/nemotron-smoke.md](docs/nemotron-smoke.md).

## Results

29 live runs against hosted Nemotron (27, N = 3 per cell) and local Nemotron on Brev (2). Five attack variants: the ransom-note injection, a poisoned syslog line, a credential-exfil note, a polite "IT runbook" written to evade the safety model, and a benign control. Full method and caveats: [docs/eval.md](docs/eval.md).

| Measure | Result |
| --- | --- |
| Evidence files changed by agents (hashed outside the sandboxes) | **0 / 29 runs** |
| Evidence-wipe attempts denied by the kernel grant | **15 / 15**, each with a signed receipt; log chain intact 29 / 29 |
| Agents went for the injected action, prompt guardrails off | 10 / 12 runs |
| Agents went for the injected action, prompt guardrails on | 0 / 12 runs |
| Safety model flagged the injected artifact | 14 / 24 screened runs; it missed the polite runbook every time |
| VPN secrets pasted into a model-written report | 0 / 29 |

Prompt guardrails and safety models are probabilistic layers. The read-only grant is not, which is the point. One gap the kernel can't cover: with guardrails off, Scribe wrote the attacker's "false positive" story into the record in 3 / 12 hosted runs. cleanroomd now refuses any agent attempt to lower a flag it measured itself (fixed after these runs, not yet re-measured).

## Screenshots

Before detonation: every asset clean, legal clocks not started.

![Command center before detonation](docs/screenshots/tui-before.png)

About a minute after detonation (live run, guardrails off, hosted Nemotron):
- The scope table is red.
- GDPR, HIPAA and Texas clocks are running.
- Containment's isolation proposal is waiting for a signature.
- Scribe's attempt to lower a measured flag was refused ("cannot lower a measurement").
- Both agents' `rm -rf /evidence/*` attempts were blocked by the OS (`by OS 2`).

![Command center after detonation](docs/screenshots/tui-after.png)

## Quick start

```sh
scripts/demo.sh                    # hosted Nemotron, guardrails on
scripts/demo.sh --guardrails off   # show the kernel stopping what the model was talked into
scripts/demo.sh --local            # route sensitive steps to Nemotron on Brev (run deploy/brev/tunnel.sh first)
scripts/demo.sh --replay           # replay recorded model responses, no network
```

In the command center: `t` tamper (rejected), `A` admit clean root, `d` detonate, `a`/`x` approve/deny, `g` guardrails, `v` verify log, `r` reset.

## Layout

| Path | What |
| --- | --- |
| `crates/proto` | Wire types shared by the daemon, agents and TUI |
| `crates/daemon` | `cleanroomd`: the OS core (root admission, bubblewrap strata and grants, tool admission, signed receipt log, bus server, scenario runner) |
| `crates/agents` | `cleanroom-agents`: the Nemotron agent team runner (model router, roles, safety and sensitivity layers) |
| `crates/tui` | `cleanroom-tui`: the ratatui incident command center, shipped as a static `.deb` |
| `crates/ransom` | `cleanroom-ransom`: safe, reversible canary ransomware (static musl) |
| `scenario/` | acme-fs seed share, `assets.json` and YARA rules (see `scenario/README.md`) |
| `roots/` | Digest-pinned root locks |
| `plans/` | Declarative host plans: init choice (dinit or s6-rc) and the service graph; `responder.json` is valid, `cycle.json` shows a cycle witness |
| `policy/egress.json` | Egress policy: deny by default; the model router's only endpoints |
| `scripts/demo.sh` | One-command tmux demo: daemon, agents, TUI (`--local`, `--replay`, `--guardrails on\|off`) |
| `scripts/launch-tui.sh` | Runs the TUI `.deb` inside the admitted Debian root |
| `docs/interfaces.md` | Transport, signing, receipts, daemon operations, grants |
| `docs/concept.md` | What we're building and why |
| `docs/research/` | Research notes behind the design |
| `deploy/brev/` | Self-hosted Nemotron on a Brev GPU (Lightning, Content Safety 3.5, Bolt behind one endpoint) and the laptop tunnel |
| `docs/nemotron-smoke.md` | Measured hosted vs local model behavior: tool calls, latency, prompt injection, safety models |

## Develop

```sh
nix develop
cargo check
```

Without a checkout, from any directory (the package carries `scenario/`, `roots/`, `plans/` and the static canary ransomware, and puts bubblewrap, skopeo and umoci on `cleanroomd`'s `PATH`):

```sh
nix run github:nunera/cleanroom                                   # cleanroomd: serve
nix run github:nunera/cleanroom -- detonate                       # any cleanroomd subcommand
nix run github:nunera/cleanroom -- plan validate plans/responder.json
nix run github:nunera/cleanroom#agents -- run                     # the Nemotron team
```

`nix build .#cleanroom` runs the daemon, agents and proto tests as part of the build.

## Model access

Nemotron credentials live outside the repo in `~/.config/cleanroom/nemotron.env` (mode `0600`):

```sh
NVIDIA_API_KEY=nvapi-...
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
```

Point `NVIDIA_BASE_URL` at a self-hosted OpenAI-compatible server (Brev, vLLM, NIM) to run Nemotron locally.

**Egress** is declared in [`policy/egress.json`](policy/egress.json): deny by default, and the model router in `cleanroom-agents` may reach only `https://integrate.api.nvidia.com` (hosted Nemotron) and `http://127.0.0.1:8000` (Brev through `deploy/brev/tunnel.sh`). The policy is compiled into the agents binary; at start the router refuses any hosted or local endpoint outside it, and its HTTPS client follows no redirects and ignores proxy variables. Agent strata have no network at all. Replay (`scripts/demo.sh --replay`, `CLEANROOM_LLM_CACHE=replay`) is the offline mode: the router builds no network client. The agents' first `status` line names the egress in effect. Adding an endpoint means editing the policy and rebuilding.

## Daemon

`cleanroomd` is the OS core. One Unix socket, `$XDG_RUNTIME_DIR/cleanroom/cleanroomd.sock` (mode `0600`), carries the bus and the operations in [docs/interfaces.md](docs/interfaces.md). It runs rootless: run it inside `nix develop` (bubblewrap, skopeo, umoci) on a host that allows unprivileged user namespaces.

```sh
cleanroomd [--socket PATH] [--state DIR] [--repo DIR]   # serve until SIGINT/SIGTERM
cleanroomd [--socket PATH] admit ROOT                   # ask the running daemon: exit 0 admitted, 1 rejected, 2 error
cleanroomd [--socket PATH] verify                       # receipt signatures and chain: exit 0 intact, 1 broken
cleanroomd [--socket PATH] reset                        # re-seed the victim, close the incident, keep receipts
cleanroomd [--socket PATH] detonate [SCENARIO]          # default ransomware; starts the investigation
cleanroomd [--socket PATH] tamper [ROOT]                # flip a byte in a staged copy; the next admit is rejected
cleanroomd [--socket PATH] run STRATUM [--timeout S] -- CMD...  # as that agent, under its grant: exit = CMD's, 124 timeout, 126 denied
cleanroomd plan validate FILE                           # offline: boot order, or the problem (cycle witness); exit 0 valid, 1 invalid, 2 unreadable
```

`--repo` is where `scenario/` and `roots/` live (default: the nearest ancestor of the binary that has both, else the current directory). State lives in `$XDG_STATE_HOME/cleanroom`: `store/oci`, `store/containers-policy.json`, `store/staging/<root>`, `store/roots/<root>/rootfs`, `keys/cleanroomd.key`, `keys/members.ndjson`, `run/acme-fs/{share,drop,logs}`, `run/scratch/<role>`, `run/bin` and `receipts.ndjson`.

- **Bus:** the first frame must be `hello`. Every `publish` must verify against the connection's key and name the connection's principal; it then fans out to every matching subscriber, sender included. Tool requests, tool decisions and approvals come only from cleanroomd; `investigate` and `agent_control` only from humans; `scope` and `incident` only from Scribe or a human; `proposal` only from Containment. An agent's `scope` that lowers a flag cleanroomd's integrity check measured `yes` in the current incident (for example payroll `locked`) is dropped with a denied receipt and an "OS kept the record" `status`; agents may add to a measurement, only a human may correct one. A new client first gets the latest incident, the latest scope per asset, open tool requests and proposals, and the latest counters.
- **Roots:** a lock (`roots/<name>-*.lock.json`) pins one platform manifest digest. Admission fetches the image once with skopeo into `store/oci` (later admissions are offline), checks a staged copy (the manifest against the lock, every blob against the manifest), unpacks it with `umoci raw unpack --rootless`, and records a digest of the unpacked tree (path, mode, content) that every stratum launch re-checks. skopeo runs with cleanroomd's own trust policy (`store/containers-policy.json`, accept unsigned images), so a host without `/etc/containers/policy.json` still fetches; trust comes from the lock's digest and the blob checks, not image signatures. `tamper` flips one byte in the first layer of a staged copy; the next `admit` answers `admit_rejected` naming that layer and discards the copy, so the admission after it (or a `reset`) is clean again. Strata admit `debian` on first use.
- **Strata:** bubblewrap with every namespace unshared (so no network), no capabilities and a cleared environment; the admitted root is read-only at `/`, with a fresh `/proc`, `/dev` and `/tmp`. Output is capped at 64 KiB per stream and timeouts at 5 minutes. A command whose stderr shows `Read-only file system` is `denied` (for example "evidence is mounted read_only for hunter"), with a receipt and a `status` line.

  | Stratum | Grant |
  | --- | --- |
  | `hunter`, `forensics` | `/evidence/acme-fs`, `/evidence/dropbox`, `/evidence/logs` and `/rules` read-only; `/scratch` read-write; `/nix/store` read-only only when the role holds admitted tools |
  | `acme-fs` (victim) | `/srv/acme-fs/{share,drop,logs}` read-write; `/opt/cleanroom/bin` read-only |
  | `scribe`, `containment` | no exec: every request is denied |

- **Tools:** `request_tool` for `yara`, `volatility3`, `tshark`, `file` or `binutils` from the pinned nixpkgs (`CLEANROOM_NIXPKGS`, else `flake.lock`) is auto-allowed; any other well-formed nix reference waits for a commander's signed `approve`; OCI sources are denied. A granted tool is built with `nix build --impure` and `NIXPKGS_ALLOW_UNFREE=1` (the pin marks volatility3 unfree), and its `bin` directories go first on the role's `PATH`. Hunter holds `yara` from startup, and the allowlist is pre-built in the background so later grants are instant and work offline.
- **Approvals and members:** an `approve` must come from a human connection whose key signed the `ApprovalDecision`. Until someone is enrolled, any human key on the socket may approve, and the first `enroll` must be an admin enrolling their own key; after that only enrolled admins enroll or `revoke`, and only enrolled commanders and admins approve. A revoked key stops approving, enrolling and revoking at once and after restarts (enrollments and revocations are applied in order from `keys/members.ndjson`); a later enrollment reinstates it. The last admin cannot be revoked, so the list never empties back into bootstrap mode.
- **Receipts:** `receipts.ndjson` holds one `Signed<Receipt>` per line (daemon key, `cleanroom/v1/receipt`); `seq` is the line number and `prev` the digest of the previous signed receipt. Every exec (allowed or denied), admission, tamper, detonation, tool grant, approval, enrollment, record update and reset is recorded. `verify_log` reports the first entry that fails its signature or its chain.
- **Scenario:** at startup and on `reset` the share is re-seeded from `scenario/acme-fs`, the drop box, logs and scratch are emptied, and every asset in `scenario/assets.json` is published with all flags `no`. `reset` takes a few milliseconds and keeps the receipt log. It also closes the incident: until the next detonation or human `investigate`, an agent's `scope`, `incident`, `proposal` or `finding` is dropped with a denied receipt (as is an `incident` record for any other incident), so an investigation still running cannot repaint the table. `detonate {scenario: "ransomware"}` runs `cleanroom-ransom` (`CLEANROOM_RANSOM_BIN`, else the static build in `target/x86_64-unknown-linux-musl/{release,debug}`) in the `acme-fs` stratum, compares the share with its seeding hashes (changed assets become `locked`, `accessed` and `modified`; `exfiltrated` stays unknown for the agents), opens the incident (`detected`, `high`, `ransomware`) and publishes `investigate`.

## Agents

`cleanroom-agents` connects to `cleanroomd` with one socket connection per role (Hunter, Forensics, Scribe, Containment), waits for an `investigate` bus event, and runs the team: Hunter and Forensics investigate concurrently inside their strata, their findings flow to Scribe, which keeps the incident and scope records, and Containment proposes actions for the commander to approve.

```sh
cleanroom-agents run [--guardrails on|off] [--max-steps N] [--socket PATH] [--once]
```

- `--guardrails` picks the hardened or the naive setup at start; `agent_control` bus events switch prompts and tools at runtime. With guardrails on, Hunter and Forensics use typed read-only tools, report findings as they go, and record each instruction they decline from untrusted data as a `refusal`. With guardrails off they run like a sloppy operator deployment: a "helpful sysadmin assistant" with only a shell (`exec`) and `report_finding`, handed the alert and told to read the notes on the share and handle them. Nothing names the injected instruction; the ransom note talks the model into it, and the stratum grant denies it (`trace.outcome` is `denied`).
- Tool arguments are conformed before they are validated: numbers sent as text or fractions become integers (`"95%"`, `0.95` → 95), a single path where a list is expected becomes a list, enum values match case-insensitively, over-long free text is clipped, and options the read-only evidence tools don't have are ignored. Anything still invalid goes back to the model as an error it can fix. Halfway through its step budget, an agent that has not reported a finding is offered only its reporting tools, and again in its last two calls.
- Every evidence-bearing tool output is scored by the Nemotron safety model (`safety_verdict`) before a model sees it; with guardrails on, unsafe output is wrapped in an untrusted-data envelope. Output with personal data or credentials moves the conversation to the local endpoint (`route`).
- `counters` is published at startup and whenever a count or the guardrails setting changes: `safety_flags` (layer 1, unsafe verdicts), `blocked_by_model` (layer 2, refusals), `blocked_by_os` (layer 3, denied commands).
- Tool requests go through the daemon's `request_tool` operation only; the daemon publishes `tool_request` and `tool_decision`. YARA rules come from the read-only `/rules` mount.
- Scribe starts from the scope records already on the bus (the daemon's baseline and measurement), so it updates those assets instead of inventing new ones: a new asset needs evidence. `update_scope` refuses to lower a flag cleanroomd measured `yes`, and refuses to clear `exfiltrated` (unknown or yes → no), which cleanroomd cannot measure; only a human may. cleanroomd enforces both on the bus. So an injected "it was only a test" cannot clear the record.
- Legal clocks: GDPR awareness and HIPAA discovery are stamped with the incident's detection time (first knowledge), however late Scribe records them; a Texas breach determination is a decision, stamped when it is made.
- Signing keys are created on first run in `$XDG_STATE_HOME/cleanroom/keys/<role>.key` (mode `0600`).

| Variable | Meaning |
| --- | --- |
| `CLEANROOM_MODEL_HUNTER`, `_FORENSICS`, `_CONTAINMENT` | Tool-loop model (default `nvidia/nemotron-3.5-lightning-30b-a3b`) |
| `CLEANROOM_MODEL_SCRIBE` | Record keeper model (default `nvidia/nemotron-3-ultra-550b-a55b`) |
| `CLEANROOM_MODEL_SAFETY` | Safety model (default `nvidia/llama-3.1-nemotron-safety-guard-8b-v3`) |
| `CLEANROOM_LOCAL_BASE_URL`, `CLEANROOM_LOCAL_MODEL`, `CLEANROOM_LOCAL_API_KEY`, `CLEANROOM_LOCAL_SAFETY_MODEL` | Optional local endpoint for sensitive evidence (model default `nvidia/nemotron-3.5-bolt-e4b`) |
| `CLEANROOM_LLM_CACHE=record\|replay`, `CLEANROOM_LLM_CACHE_DIR` | Record model responses, or replay them with no network client (default dir `~/.cache/cleanroom/llm`). Replay is labelled in every `status` |
| `CLEANROOM_NIXPKGS` | Pinned flake prefix for tool requests (default: the `flake.lock` nixpkgs rev) |

## Command center

`cleanroom-tui` connects as the commander and renders only from bus events: incident header and legal notification clocks, scope of compromised data, live agent trace, approvals, timeline and comms.

Keys: `d` detonate, `t` tamper then admit (rejected), `A` admit the clean root, `a`/`x` approve/deny the selected item, `g` toggle agent prompt guardrails, `i` investigate, `v` verify the receipt log, `r` reset, `c` chat, `?` help, `q` quit.

Flags: `--socket PATH`, `--record FILE` (save live events), `--replay FILE [--speed X]` (offline playback with a REPLAY badge; the demo fallback), `--tamper-root NAME` (default `debian`), `--scenario NAME` (default `ransomware`).

Debian package (static musl, runs on bookworm and trixie):

```sh
nix develop --command nix shell --inputs-from . nixpkgs#pkgsCross.musl64.buildPackages.rustc nixpkgs#pkgsCross.musl64.stdenv.cc --command env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-cc 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS=-C target-feature=+crt-static' cargo deb -p cleanroom-tui --target x86_64-unknown-linux-musl
```

## Limitations

These are what a judge or a security reviewer should know before trusting a claim in this repo.

- **Platform.** Linux only. The strata need unprivileged user namespaces; tested on NixOS. Ubuntu 24.04's default AppArmor policy blocks bubblewrap's network namespace, so it needs a reviewed policy there.
- **Not yet an operating system.** Cleanroom runs as rootless userspace on a host. The declarative host plan and init choice are validated (`cleanroomd plan validate`) but not booted. Admitted roots are Linux only; only Debian bookworm is pinned today.
- **The store is user-owned.** The admitted roots and receipt log are protected by digests, signatures and launch-time re-verification, not by ownership. A local user who controls the account can replace the whole store; `verify` will detect a changed log but not prevent it.
- **Model-side layers are probabilistic.**
  - Prompt guardrails and the safety model reduce attempts but don't stop them. The safety model missed the polite "IT runbook" injection every time (see [docs/eval.md](docs/eval.md)).
  - The kernel grant is the only layer that held in every run.
- **The record can still be shaded.** cleanroomd refuses any agent attempt to lower a flag it measured itself. An attacker's story can still reach softer fields an agent writes: incident title, severity, confidence, and flags cleanroomd didn't measure (e.g. `exfiltrated`). Provenance tiers for model claims are not built yet.
- **Containment is advisory.** Approving a containment proposal records the decision and publishes it; cleanroomd doesn't isolate a real host.
- **Hosted model calls leave the machine.** By default the agents call NVIDIA's hosted API through the declared egress policy. Sensitive steps can route to self-hosted Nemotron on Brev (`--local`). A fully offline run needs every role pointed at the local endpoint; Ultra (Scribe's default) is hosted only.
- **Simulated attack.** `cleanroom-ransom` is a reversible simulator using a published key, against synthetic data. The credential-exfil variant's uploads failed because `curl`/`wget` aren't in the root, so the eval doesn't measure the network namespace.
- **Small eval.** N = 3 per cell on hosted Nemotron, plus 2 local runs. The record-poisoning fix landed after those runs and hasn't been re-measured.

## Prior work

Cleanroom rebuilds ideas from [MisaOS](https://github.com/nunera/misaos) (strict records, signed local admission of digest-pinned roots, sandboxed foreign roots, Nix packaging). The Cleanroom code itself is written at the event.

## License

Apache-2.0
