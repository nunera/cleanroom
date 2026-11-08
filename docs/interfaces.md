# Interfaces

This is the contract between the three parts of Cleanroom. The Rust source of truth is `crates/proto/src/lib.rs` (`cleanroom-proto`); this page explains how the pieces fit together.

| Component | Owner | Talks to |
| --- | --- | --- |
| `cleanroomd`: OS core (admission, strata, grants, receipts, bus server, scenarios) | Teammate | Everyone, over one Unix socket |
| Agents: Nemotron loop, roles, model router | Michael | `cleanroomd` (exec, tool requests, bus) and the model endpoint |
| TUI: ratatui command center, shipped as a `.deb` | Michael | `cleanroomd` (bus events, approvals, detonate, tamper, verify) |

## Transport

- One Unix socket: `$XDG_RUNTIME_DIR/cleanroom/cleanroomd.sock`, owned by `cleanroomd`, mode `0600`.
- Newline-delimited JSON. One line = one `Envelope`: `{"v":1,"frame":"<kind>",...}`.
- The first frame from every client is `hello`, naming its principal, the raw Ed25519 public key that signs its `publish` frames, and the audiences it subscribes to. There is no acknowledgement frame.
- A subscriber receives every message whose `to` matches one of its audiences; messages addressed to `all` reach everyone.
- **State on connect:** right after `hello`, the daemon replays the current state to that client as `event` frames: the latest `incident`, the latest `scope` per asset, open tool requests and proposals, and the latest `counters`. At startup and after `reset`, it publishes a baseline `scope` record for every asset with all flags `no`, so the command center can show the all-green "before" screen.
- `request` / `response` frames carry an `id` chosen by the client; the daemon answers with the same `id`.
- `publish` frames go from clients to the daemon. The daemon checks the signature, appends a receipt if relevant, and fans the message out as `event` frames to every matching subscriber, **including the sender** (the TUI renders only from events, so it relies on seeing its own chat and toggles echoed back).
- Agent strata have no network and no access to the socket. The agent *runner* (outside the strata) holds the socket connection and calls `exec` on the agent's behalf; the daemon applies that role's grant.

## Signing

- Ed25519. A key id is `sha256:<hex>` of the raw 32-byte public key.
- Signed bytes: `domain + "\n" + hex(sha256(JCS(body)))`, where JCS is RFC 8785 canonical JSON. Domains are in `cleanroom_proto::domain`.
- No floats on the wire (percentages are `u8`), so canonical JSON stays unambiguous.
- Each agent role has its own key; humans have their own keys, enrolled by an admin (`Signed<Member>` under `cleanroom/v1/enroll`) and revoked by an admin (`Signed<Revocation {key_id, reason, revoked_at}>` under `cleanroom/v1/revoke`).
- Use `cleanroom_proto::sign` (`sign`, `verify`, `digest_of`, `key_id`, `generate_key`, `signing_key_from_hex`, `verifying_key_from_hex`) on both sides so the bytes always match. `digest_of` is also how a receipt computes `prev`.

## Receipts

Every allowed or denied action appends a `Receipt` to a hash-chained log. `prev` is the digest of the previous signed receipt; the first entry uses `sha256:` followed by 64 zeros. `verify_log` walks the chain offline and reports the first break.

Receipt actions: `admit_root`, `exec`, `write`, `tool_grant`, `approval`, `enroll`, `revoke`, `record_update`, `detonate`, `evidence_seal`, `model_call`.

## Daemon operations (`request.op`)

| op | Who calls it | Response |
| --- | --- | --- |
| `exec` | Agent runner | `exec` with outcome `exited` / `timed_out` / `denied` + `receipt_seq` |
| `request_tool` | Agent runner | `tool` with decision `auto_allowed` / `approved` / `denied` / `pending` |
| `model_call` | Agent runner | Body is `ModelCall {from, purpose, model, endpoint, request, response, replayed, latency_ms}`: one model call (agent step, chat turn or safety verdict) with `sha256:` digests of the exact request and response bytes. Sent on the connection of the role named in `from`. Response `ok`; the daemon chains a `model_call` receipt as that agent |
| `approve` | TUI (commander) | Body is `Signed<ApprovalDecision {subject_id, approved, at}>` under `cleanroom/v1/approval`. Response `ok`, then a `tool_decision` or `approval` bus event |
| `enroll` | TUI (admin) | `ok` or `error` |
| `revoke` | TUI (admin) | Body is `Signed<Revocation>` under `cleanroom/v1/revoke`. `ok`, or `error` when the signer is not an enrolled admin, the key is not enrolled, or it is the last admin. A later `enroll` of the same key reinstates it |
| `detonate` | TUI | `ok`; scenario progress arrives as bus events, then the daemon publishes `investigate`. Scenario names: `ransomware` (exfil/persistence are stretch) |
| `tamper` | TUI (demo opener) | `ok`. `root` names an admitted root; the demo uses `debian` |
| `admit` | TUI / CLI | `admitted` or `admit_rejected` (names the layer, expected and actual digest) |
| `verify_log` | TUI | `log_verified { entries, first_break }` |
| `reset` | TUI / CLI | `ok` |

## Bus messages (`body.type`)

`chat`, `finding`, `proposal`, `approval`, `tool_request`, `tool_decision`, `trace` (one agent loop step; `outcome` is set when the step ran a command, and `denied` means the grant blocked it), `refusal` (an agent declined an instruction found in untrusted data: blocked by the model), `counters` (running totals: blocked by model, blocked by OS, safety flags, guardrails on/off, LLM mode `live`/`record`/`replay`), `safety_verdict` (Nemotron safety model on an untrusted artifact), `route` (local vs hosted model decision), `scope` (a full `ScopeRecord`), `incident` (a full `IncidentRecord`), `status` (free text for humans), `investigate` (starts the agent team on an incident; the daemon publishes it after a detonation, or the TUI does), `agent_control` (commander toggles `guardrails`; off swaps the hardened agent prompt for a naive one so the demo can show the kernel grant blocking what the model was talked into).

**Tool requests:** agents send only the `request_tool` op. The daemon publishes the `tool_request` event and, when decided, the `tool_decision` event.

**Conversation with the Lead agent.** `Role::Lead` is the commander's point of contact. It has no stratum and no exec. All of it rides on `chat`:
- **Human → Lead:** `chat` from `Human` to `role: lead`. The Cleanroom screen sends every message this way.
- **Lead → humans:** `chat` from `Agent{lead}` to `humans`. These are answers plus short narration of key events (detonation, OS block, finding, proposal waiting).
- **Lead → specialist:** `chat` from `Agent{lead}` to `role: <hunter|forensics|scribe|containment>`, starting with the question.
- **Specialist → Lead:** `chat` from `Agent{<role>}` to `role: lead`. A human may also message a specialist directly (`to: role: <role>`); the reply then goes to `humans`.
- The command center renders these as a conversation and lights the Lead↔specialist link while a delegation is open.

The TUI renders state from these events alone; it never reads the agents' files.

## Grants (per stratum)

| Stratum | Root | Mounts | Network | Notes |
| --- | --- | --- | --- | --- |
| `hunter` | Debian root | evidence `read_only`, rules `/rules` `read_only`, scratch `read_write` | none | logs, YARA |
| `forensics` | Debian root + Nix tools | evidence `read_only`, rules `/rules` `read_only`, scratch `read_write` | none | volatility3 / tshark via tool requests |
| `scribe` | minimal | incident record `append_only` (through the daemon) | none | no shell tools |
| `containment` | none | none | none | proposals only; commander must approve |
| `acme-fs` | Debian root | company share `read_write` | none | victim; the scenario runs here |
| model router | host process | none | egress to the model endpoint only | the only process with network |

## Incident record and scope

- `IncidentRecord` follows a NIST SP 800-61r3 aligned subset: status lifecycle `detected → analyzing → contained → eradicated → recovered → closed`, severity, category, timeline with evidence references.
- `Triggers` holds the start event for each legal clock: GDPR (`aware_at`, 72 hours), HIPAA (`discovered_at`, 60 days), Texas §521.053 (`breach_determined_at`, 60 days; Attorney General within 30 days when `texas_residents` ≥ 250), SEC 8-K Item 1.05 (`materiality_determined_at`, 4 business days).
- `ScopeRecord` keeps independent flags (`locked`, `exfiltrated`, `accessed`, `destroyed`, `modified`), each `yes` / `no` / `unknown` (default `unknown`), plus evidence and a 0–100 confidence.

## Examples

These were produced by serializing the Rust types and round-trip checked.

```json
{"v":1,"frame":"hello","principal":{"kind":"agent","role":"hunter"},"public_key":"<64 hex>","subscribe":[{"kind":"all"}]}
{"v":1,"frame":"request","id":7,"request":{"op":"exec","from":"hunter","stratum":"hunter","argv":["rm","-rf","/evidence"],"timeout_ms":10000}}
{"v":1,"frame":"response","id":7,"response":{"result":"exec","outcome":{"kind":"denied","reason":"evidence is mounted read_only for hunter"},"stdout":"","stderr":"","truncated":false,"receipt_seq":42}}
{"v":1,"frame":"publish","domain":"cleanroom/v1/bus","body":{"id":"msg-01","at":"2026-11-08T01:23:45Z","from":{"kind":"agent","role":"forensics"},"to":{"kind":"all"},"body":{"type":"tool_request","id":"tool-03","from":"forensics","stratum":"forensics","tool":"volatility3","source":{"kind":"nix","flake_ref":"github:NixOS/nixpkgs/<rev>#volatility3"},"reason":"memory image analysis"}},"signer":"sha256:<key>","sig":"<hex>"}
```

## Changing the contract

Change `crates/proto` first, then this page, in the same commit. Tell the other person before pushing; both sides depend on it.
