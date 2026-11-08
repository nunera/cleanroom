# Cleanroom

When an attacker owns your network, the first thing you can't trust is your own tools.

Cleanroom is a responder OS for cyber incidents. Every tool, Linux root and agent environment is declared, pinned by digest and admitted by signature before it runs. Nemotron agents investigate inside sandboxed strata, each with only the access its role needs, and a ratatui command center shows the incident, the scope of compromised data and the legal notification clocks as they unfold.

Built at HackUTD 2026 (ZeroDay) for the NVIDIA and Winstead tracks.

## Status

The full demo runs end to end on one Linux laptop:
- **Admission:** the Debian and Alpine roots are admitted by digest. A tampered byte is rejected, naming the layer, and the clean copy is re-admitted.
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

Live run, guardrails off, hosted Nemotron, captured from tmux at 160×45. The banner's sky follows the incident: teal while everything is clean, a red sunset once assets are compromised, amber at the horizon while something waits for a signature.

**Overview** (F1): what to do next, with the key for each line; the incident; every asset's flags; what each defense layer stopped; the nearest legal deadlines.

![Overview tab](docs/screenshots/overview.png)

**Lead** (F2): the conversation with the Lead agent and its delegations to the specialists, the team with live status, and the red banner pinned for 8 seconds after the kernel blocks an agent.

![Lead tab](docs/screenshots/lead.png)

**Defense** (F5): every kernel denial with its receipt, the model's refusals, the safety verdicts, the guardrails setting and the receipt log.

![Defense tab](docs/screenshots/defense.png)

**Controlroom** (F10): the complete operator screen. Every OS denial stays pinned at the top with its receipt; below are the legal clocks, the scope table, the one-line agent trace over the Lead conversation, and the team, approvals, defense layers and timeline.

![Controlroom](docs/screenshots/controlroom.png)

## Quick start

```sh
scripts/demo.sh                    # hosted Nemotron, guardrails on
scripts/demo.sh --guardrails off   # show the kernel stopping what the model was talked into
scripts/demo.sh --local            # route sensitive steps to Nemotron on Brev (run deploy/brev/tunnel.sh first)
scripts/demo.sh --replay           # replay recorded model responses, no network
```

In the command center: `F1`–`F6` and `F10` pick a tab (Overview, Lead, Scope, Record, Defense, Team, Controlroom); on the Lead tab type to the Lead and press Esc for keys. Keys: `t` tamper (rejected), `A` admit clean root, `d` detonate, `a`/`x` approve/deny, `g` guardrails, `v` verify log, `r` reset, `m` members.

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
cleanroomd [--socket PATH] probe [hunter|forensics]    # test the stratum's walls from inside, one receipt per wall: exit 0 all held, 1 one broken
cleanroomd reasoning SEQ [--state DIR]                 # offline: the Nemotron reasoning behind model_call receipt SEQ; exit 0 matches the signed digest, 1 changed
cleanroomd plan validate FILE                           # offline: boot order, or the problem (cycle witness); exit 0 valid, 1 invalid, 2 unreadable
```

`--repo` is where `scenario/` and `roots/` live (default: the nearest ancestor of the binary that has both, else the current directory). State lives in `$XDG_STATE_HOME/cleanroom`: `store/oci`, `store/containers-policy.json`, `store/staging/<root>`, `store/roots/<root>/rootfs`, `keys/cleanroomd.key`, `keys/members.ndjson`, `run/acme-fs/{share,drop,logs}`, `run/scratch/<role>`, `run/bin` and `receipts.ndjson`.

- **Bus:** the first frame must be `hello`. Every `publish` must verify against the connection's key and name the connection's principal; it then fans out to every matching subscriber, sender included. Tool requests, tool decisions and approvals come only from cleanroomd; `investigate` and `agent_control` only from humans; `scope` and `incident` only from Scribe or a human; `proposal` only from Containment. An agent's `scope` that lowers a flag cleanroomd's integrity check measured `yes` in the current incident (for example payroll `locked`) is dropped with a denied receipt and an "OS kept the record" `status`; agents may add to a measurement, only a human may correct one. A new client first gets the latest incident, the latest scope per asset, open tool requests and proposals, and the latest counters.
- **Roots:** a lock (`roots/<name>-*.lock.json`) pins one platform manifest digest. Two are pinned: `debian` (`debian:bookworm-slim`) and `alpine` (`alpine:3.21`, 3.21.10, busybox userland). Admission fetches the image once with skopeo into `store/oci` (later admissions are offline), checks a staged copy (the manifest against the lock, every blob against the manifest), unpacks it with `umoci raw unpack --rootless`, and records a digest of the unpacked tree (path, mode, content) that every stratum launch re-checks. skopeo runs with cleanroomd's own trust policy (`store/containers-policy.json`, accept unsigned images), so a host without `/etc/containers/policy.json` still fetches; trust comes from the lock's digest and the blob checks, not image signatures. `tamper` flips one byte in the first layer of a staged copy; the next `admit` answers `admit_rejected` naming that layer and discards the copy, so the admission after it (or a `reset`) is clean again. Each stratum admits its own root on first use, and cleanroomd refuses to start if a stratum's root has no lock.
  - To pin a root, resolve the linux/amd64 platform manifest (not the multi-arch index) and check its digest: `skopeo inspect --raw docker://docker.io/library/alpine:3.21 | jq -r '.manifests[] | select(.platform.os=="linux" and .platform.architecture=="amd64") | .digest'`, then `skopeo inspect --raw docker://docker.io/library/alpine@<digest> | sha256sum` must print the same digest.
- **Strata:** bubblewrap with every namespace unshared (so no network), no capabilities and a cleared environment; the admitted root is read-only at `/`, with a fresh `/proc`, `/dev` and `/tmp`. No stratum can create a nested user namespace (`--disable-userns`, so `unshare -U -r` fails instead of handing a steered command uid 0 in a new namespace), and bubblewrap refuses to start one where it cannot enforce that (`--assert-userns-disabled`). Output is capped at 64 KiB per stream and timeouts at 5 minutes. A command whose stderr shows `Read-only file system` is `denied` (for example "evidence is mounted read_only for hunter"), with a receipt and a `status` line.

  | Stratum | Root | Grant |
  | --- | --- | --- |
  | `hunter` | `debian` | `/evidence/acme-fs`, `/evidence/dropbox`, `/evidence/logs` and `/rules` read-only; `/scratch` read-write; `/nix/store` read-only only when the role holds admitted tools |
  | `forensics` | `alpine` | same as `hunter` |
  | `acme-fs` (victim) | `debian` | `/srv/acme-fs/{share,drop,logs}` read-write; `/opt/cleanroom/bin` read-only |
  | `rule-check` | `debian` | see agent-written detection rules below |
  | `scribe`, `containment` | none | no exec: every request is denied |

  `CLEANROOM_ROOTS` moves strata onto other admitted roots, for example `CLEANROOM_ROOTS=forensics=debian` (comma-separated `stratum=root` pairs; strata it doesn't name keep their default). The agents' file tools (`ls -la`, `head -c`, `grep -rnE`, `sha256sum`, `find -exec`) are busybox on Alpine and GNU coreutils on Debian; admitted Nix tools bring their own libraries from `/nix/store`, so they run on either root.

- **Probe:** `cleanroomd probe [hunter|forensics]` tests those walls from inside the stratum, as its agent under its grant, one command and one signed receipt per wall: only `lo` in `/proc/net/dev`, `CapEff` all zero, `unshare -U` refused, nothing in the environment but `HOME`, `LANG`, `TMPDIR`, `PATH` and `PWD` (a leaked variable is named, its value never printed), a write under `/evidence` denied by the kernel, and the invoking user's `$HOME` absent. It prints `PASS`/`FAIL` per wall with the receipt number and exits 1 if any wall is broken.
- **Tools:** `request_tool` for `yara`, `volatility3`, `tshark`, `file` or `binutils` from the pinned nixpkgs (`CLEANROOM_NIXPKGS`, else `flake.lock`) is auto-allowed; any other well-formed nix reference waits for a commander's signed `approve`; OCI sources are denied. A granted tool is built with `nix build --impure` and `NIXPKGS_ALLOW_UNFREE=1` (the pin marks volatility3 unfree), and its `bin` directories go first on the role's `PATH`. Hunter holds `yara` from startup, and the allowlist is pre-built in the background so later grants are instant and work offline.
- **Agent-written detection rules:** Hunter writes a YARA rule for the attack it found and sends it with `submit_rule`. cleanroomd runs it under `yara` in a sandbox (no network, everything read-only) twice: over the clean seed files from before the attack, then over the evidence. It admits the rule into `/rules/agent-<name>.yar` only if it compiles, matches no clean file and matches some evidence; otherwise the agent gets the reason (YARA's error, the clean files it hit, or "matches no evidence") and can fix it. Either way the verdict is a `yara_rule` receipt (allowed or denied, with the rule's digest) and a `status` line. `/rules` is cleanroomd's copy of `scenario/rules`, restored at every seeding, so admitted rules last for one incident. The model writes the rule; the OS decides whether it ships.
- **Approvals and members:** an `approve` must come from a human connection whose key signed the `ApprovalDecision`. Until someone is enrolled, any human key on the socket may approve, and the first `enroll` must be an admin enrolling their own key; after that only enrolled admins enroll or `revoke`, and only enrolled commanders and admins approve. A revoked key stops approving, enrolling and revoking at once and after restarts (enrollments and revocations are applied in order from `keys/members.ndjson`); a later enrollment reinstates it. The last admin cannot be revoked, so the list never empties back into bootstrap mode.
- **Receipts:** `receipts.ndjson` holds one `Signed<Receipt>` per line (daemon key, `cleanroom/v1/receipt`); `seq` is the line number and `prev` the digest of the previous signed receipt. Every exec (allowed or denied), admission, tamper, detonation, tool grant, approval, enrollment, record update and reset is recorded. So is every model call the agent runner makes (`model_call`, as the agent it was for: purpose, model, endpoint, `sha256:` of the exact request and response bytes, and whether the answer was replayed), so the log shows which model produced what. `verify_log` reports the first entry that fails its signature or its chain.
- **Evidence seal:** at detection cleanroomd hashes every file under `/evidence/acme-fs`, `/evidence/dropbox` and `/evidence/logs` into one digest (`evidence_seal` receipt, with a status line). After every agent command it hashes them again: a denied command's status line adds "evidence unchanged: still matches the seal from receipt #N", which holds however the command hid its errors; a change (agents mount the evidence read-only, so it came from elsewhere) is resealed with a new receipt and an `EVIDENCE CHANGED` status naming the files. `verify_log` also compares the evidence with the seal taken at detection and names every changed, added or removed file, so a later reseal never hides a change. `reset` drops both seals.
- **Reasoning custody:** Nemotron returns its chain of thought (`reasoning_content`) beside every answer. The agent runner sends it with each `model_call`; cleanroomd stores it in `reasoning.ndjson` (append-only, mode `0600`) under the receipt's number and puts its `sha256:` and the reasoning-token count in the signed receipt. `cleanroomd reasoning SEQ` works offline: it checks that receipt's signature against the daemon key and whether the stored trace still matches the signed digest, so the record shows why a model chose each step and an edited trace is caught. Safety Guard verdicts carry no trace.
- **Citation checks:** when an agent publishes a `finding`, cleanroomd checks every `/evidence/...` path it cites: does it exist in the evidence, and did a command cleanroomd ran for that agent touch it or a directory above it? The result is a `status` line ("citations in hunter's finding: all 2 cited evidence paths exist and were touched by hunter's commands", or "5 of 6 hold up; /evidence/yara_scan does not exist" / "… was never touched by hunter" / "… is a wildcard, not a file"). The finding is never dropped; a model that invents a source or cites a file it never opened is named in the record. Paths with `..` never count as existing.
- **Scenario:** at startup and on `reset` the share is re-seeded from `scenario/acme-fs`, the drop box, logs and scratch are emptied, and every asset in `scenario/assets.json` is published with all flags `no`. `reset` takes a few milliseconds and keeps the receipt log. It also closes the incident: until the next detonation or human `investigate`, an agent's `scope`, `incident`, `proposal` or `finding` is dropped with a denied receipt (as is an `incident` record for any other incident), so an investigation still running cannot repaint the table. `detonate {scenario: "ransomware"}` runs `cleanroom-ransom` (`CLEANROOM_RANSOM_BIN`, else the static build in `target/x86_64-unknown-linux-musl/{release,debug}`) in the `acme-fs` stratum, compares the share with its seeding hashes (changed assets become `locked`, `accessed` and `modified`), and hashes the drop box too: a file there with the same bytes as a seeded file is a staged copy, which makes its asset `accessed` with the copy as evidence (`/evidence/dropbox/payroll.csv: byte-for-byte copy of /evidence/acme-fs/payroll.csv`), and the incident summary and the agents' brief name the copies. `exfiltrated` stays unknown for the agents: a copy on the host is not proof that it left. It then opens the incident (`detected`, `high`, `ransomware`) and publishes `investigate`.

## Agents

`cleanroom-agents` connects to `cleanroomd` with one socket connection per role (Lead, Hunter, Forensics, Scribe, Containment), waits for an `investigate` bus event, and runs the team: Hunter and Forensics investigate concurrently inside their strata, their findings flow to Scribe, which keeps the incident and scope records, and Containment proposes actions for the commander to approve. The Lead is the commander's point of contact and stays up across incidents (with `--once`, the runner exits after the first investigation).

```sh
cleanroom-agents run [--guardrails on|off] [--max-steps N] [--socket PATH] [--once]
```

- `--guardrails` picks the hardened or the naive setup at start; `agent_control` bus events switch prompts and tools at runtime. With guardrails on, Hunter and Forensics use typed read-only tools, report findings as they go, and record each instruction they decline from untrusted data as a `refusal`. With guardrails off they run like a sloppy operator deployment: a "helpful sysadmin assistant" with only a shell (`exec`) and `report_finding`, handed the alert and told to read the notes on the share and handle them. Nothing names the injected instruction; the ransom note talks the model into it, and the stratum grant denies it (`trace.outcome` is `denied`).
- **Lead:** it keeps a live picture of the incident from bus events alone: the incident, scope per asset, findings, refusals, OS denials (`trace.outcome` `denied`), counters, proposals and tool requests waiting for the commander, and the legal clocks from the incident's triggers. It narrates key events to `humans` in short templated lines, with no model call and at most one line every 4 s: the detonation, each agent's first OS denial (with the file it had just read and the receipt number), each agent's first finding, proposals waiting for a decision (merged when several arrive together), and Scribe's scope changes. A human `chat` to `role: lead` gets exactly one answer, from Nemotron (Lightning by default), even when the model fails; narration waits while the Lead answers. The Lead's tools are `get_situation`, `ask_agent` (a `chat` to a specialist's role, then up to 45 s for its answer) and `reply`. Its prompt is always the hardened one, whatever the guardrails setting, and an answer that claims an approval goes back to the model to be rewritten: approvals are human-only.
- **Specialists answer questions:** a `chat` to a specialist's role from the Lead or a human gets one short answer from that specialist's model, with its current prompt and what it has done in this incident (its findings, refusals, denied commands and latest steps; Scribe also sees the records, Containment its proposals). It runs no tools and nothing new, beside the investigation loop, never blocking it. The answer goes to `role: lead`, or to `humans` when a human asked. Conversation turns replay from their own `<role>.chat` streams, so questions never shift a recorded investigation.
- Tool arguments are conformed before they are validated: numbers sent as text or fractions become integers (`"95%"`, `0.95` → 95), a single path where a list is expected becomes a list, enum values match case-insensitively, over-long free text is clipped, and options the read-only evidence tools don't have are ignored. Anything still invalid goes back to the model as an error it can fix. Halfway through its step budget, an agent that has not reported a finding is offered only its reporting tools, and again in its last two calls.
- Every evidence-bearing tool output is scored by the Nemotron safety model (`safety_verdict`) before a model sees it; with guardrails on, unsafe output is wrapped in an untrusted-data envelope. Output with personal data or credentials moves the conversation to the local endpoint (`route`).
- `counters` is published at startup and whenever a count or the guardrails setting changes: `safety_flags` (layer 1, unsafe verdicts), `blocked_by_model` (layer 2, refusals), `blocked_by_os` (layer 3, denied commands). A denied command's `trace.result_preview` ends with its receipt, ` (receipt #42)`.
- Tool requests go through the daemon's `request_tool` operation only; the daemon publishes `tool_request` and `tool_decision`. YARA rules come from the read-only `/rules` mount.
- Scribe starts from the scope records already on the bus (the daemon's baseline and measurement), so it updates those assets instead of inventing new ones: a new asset needs evidence. `update_scope` refuses to lower a flag cleanroomd measured `yes`, and refuses to clear `exfiltrated` (unknown or yes → no), which cleanroomd cannot measure; only a human may. cleanroomd enforces both on the bus. So an injected "it was only a test" cannot clear the record.
- Legal clocks: GDPR awareness and HIPAA discovery are stamped with the incident's detection time (first knowledge), however late Scribe records them; a Texas breach determination is a decision, stamped when it is made.
- Reasoning budgets: `policy/reasoning.json` (compiled in) sets how many tokens each role's Nemotron model may spend reasoning per step, sent as `reasoning_budget` on agent steps and the Lead's turns (specialists' answers turn thinking off; safety verdicts carry neither). Every budget must leave 512 of the step's 2,048 tokens for the answer, so a model can no longer reason away its whole step and answer nothing. The budgets are in the startup `status` line, and the `model_call` receipts record the reasoning tokens actually spent.
- Training-ready tags: the runner (not the model) appends one JSON line per tool call to `$XDG_STATE_HOME/cleanroom/dataset/<incident>.jsonl` (directory `0700`, files `0600`; the incident id is reduced to letters, digits, `-` and `_`). A tag records the role, step, model and route; the tool and what it read; the step's shape (`long_context` for reads of 8,000+ characters, `needle_lookup`, `listing`, `tool_request`, `record_writing`, `planning`, `refusal`); provenance (`attacker_writable` evidence, `cleanroom` rules, `agent_claim`); and the cleanroomd receipt number of the command. A step is `trainable` only with guardrails on, when the grant did not deny it and the safety model did not flag (or fail to score) what it read. Nothing is trained here; the tags are the data a fine-tune would filter on.
- NeMo Gym export: `cleanroom-agents export-gym --incident INC-… --out pivots.jsonl` turns an incident into NeMo Gym training data in the `single_step_tool_use_with_argument_comparison` pivot format: one row per model call, with the request prefix as Responses input items, the offered tools, and the call the model made as `expected_action` (`function_call`, `function_call_batch` or `message`), plus the model's reasoning as `reference_output` and a `cleanroom` provenance object (incident, role, step, model, request digest, the receipts of the commands it ran). Only calls whose every step is `trainable` are exported. Each tag carries the `sha256:` of the request that chose it, and the exact request and response come from the record cache, so the incident must run with `CLEANROOM_LLM_CACHE=record`. A live run gave 36 rows (30 single calls, 6 parallel batches; 2 calls skipped as untrainable) that pass NeMo Gym's own `validate_pivot_dataset.py` structural checks (its optional Pydantic check, which needs a Gym install, was not run).
- Reset stops the team: when cleanroomd publishes an asset's baseline (a `system` scope record with every flag `no`, which it does only on `reset`), the runner aborts the running investigation and posts "acme-fs was reset: stopped the team on INC-…", so no model call or command is spent on a closed incident. A live reset 40 s into an investigation: 45 model calls before the reset receipt, none and no agent command in the 45 s after it.
- Signing keys are created on first run in `$XDG_STATE_HOME/cleanroom/keys/<role>.key` (mode `0600`). The startup `status` line ("agents online on …") and each "investigating …" line end with each role's hosted model, `models: lead=<id>, hunter=<id>, …`.

| Variable | Meaning |
| --- | --- |
| `CLEANROOM_MODEL_LEAD` | The Lead's chat model (default `nvidia/nemotron-3.5-lightning-30b-a3b`) |
| `CLEANROOM_MODEL_HUNTER`, `_FORENSICS`, `_CONTAINMENT` | Tool-loop model (default `nvidia/nemotron-3.5-lightning-30b-a3b`) |
| `CLEANROOM_MODEL_SCRIBE` | Record keeper model (default `nvidia/nemotron-3-ultra-550b-a55b`) |
| `CLEANROOM_MODEL_SAFETY` | Safety model (default `nvidia/llama-3.1-nemotron-safety-guard-8b-v3`) |
| `CLEANROOM_LOCAL_BASE_URL`, `CLEANROOM_LOCAL_MODEL`, `CLEANROOM_LOCAL_API_KEY`, `CLEANROOM_LOCAL_SAFETY_MODEL` | Optional local endpoint for sensitive evidence (model default `nvidia/nemotron-3.5-bolt-e4b`) |
| `CLEANROOM_LLM_CACHE=record\|replay`, `CLEANROOM_LLM_CACHE_DIR` | Record model responses, or replay them with no network client (default dir `~/.cache/cleanroom/llm`). Replay is labelled in every `status` |
| `CLEANROOM_NIXPKGS` | Pinned flake prefix for tool requests (default: the `flake.lock` nixpkgs rev) |

## Command center

`cleanroom-tui` connects as the commander and renders only from bus events. It is a row of tabs under a pixel-art banner whose sky shows the incident's state; `F1`–`F6` and `F10` pick a tab, `Tab`/`Shift+Tab` cycle:
- **Overview** (F1): the next step and what needs you, each line naming the key that acts on it; the incident; assets with a flag strip; bars per defense layer; the nearest legal deadlines.
- **Lead** (F2): the conversation with the Lead agent, its delegations to the specialists as compact cards, key system events as one-line markers, and the team (status, model, last action; a Lead↔specialist link lights while a delegation is open). A kernel denial pins a red banner over the conversation for 8 seconds.
- **Scope** (F3): one card per asset with every flag, classes, records, Texans, confidence and evidence.
- **Record** (F4): the incident record, its timeline and all five legal clocks with deadlines and duties.
- **Defense** (F5): every kernel denial with its receipt, refusals, safety verdicts, guardrails and the receipt log (`v` verifies).
- **Team** (F6): the Lead and each specialist with model, route, status, recent steps and findings.
- **Controlroom** (F10): every OS denial pinned with agent, command and receipt; clocks, scope table, one-line agent trace (select a step to expand it) over the Lead conversation; team, approvals, defense layers and timeline beside them.

The Lead tab opens with the message line focused: everything typed is text, Enter sends it to the Lead, and `@hunter …` (or any agent name or its first letters) sends it to that specialist. Esc leaves the line for the command keys; Enter or `c` returns. On every other tab the letters are commands, and daemon answers show in a corner toast.

Keys: `d` detonate, `t` tamper then admit (rejected), `A` admit the clean root, `a`/`x` approve/deny the selected item, `g` toggle agent prompt guardrails, `i` investigate, `v` verify the receipt log, `r` reset, `c` chat, `m` access control (enroll a member by public key, name and role, or revoke one; signed with the commander key), `PgUp`/`PgDn` scroll the conversation, `←`/`→` switch Controlroom panes, `?` help, `q` quit. `NO_COLOR` turns color off.

Flags: `--socket PATH`, `--record FILE` (save live events), `--replay FILE [--speed X]` (offline playback with a REPLAY badge; the demo fallback), `--tamper-root NAME` (default `debian`), `--scenario NAME` (default `ransomware`).

Debian package (static musl, runs on bookworm and trixie):

```sh
nix develop --command nix shell --inputs-from . nixpkgs#pkgsCross.musl64.buildPackages.rustc nixpkgs#pkgsCross.musl64.stdenv.cc --command env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-cc 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS=-C target-feature=+crt-static' cargo deb -p cleanroom-tui --target x86_64-unknown-linux-musl
```

## Limitations

These are what a judge or a security reviewer should know before trusting a claim in this repo.

- **Platform.** Linux only. The strata need unprivileged user namespaces; tested on NixOS. Ubuntu 24.04's default AppArmor policy blocks bubblewrap's network namespace, so it needs a reviewed policy there.
- **Not yet an operating system.** Cleanroom runs as rootless userspace on a host. The declarative host plan and init choice are validated (`cleanroomd plan validate`) but not booted. Admitted roots are Linux only, amd64 only; Debian bookworm and Alpine 3.21 are pinned today.
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
