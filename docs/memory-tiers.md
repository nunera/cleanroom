# Memory tiers: the evidence pager

Opt-in: `cleanroom-agents run --memory-tiers`, `CLEANROOM_MEMORY_TIERS=1`, or `scripts/demo.sh --memory-tiers`. Without it the agents behave exactly as before.

An agent's context is a list of spans. Each span has a source, and the source decides how the span enters: exact (the bytes themselves) or compressed (a handle). Attacker-written evidence that is more than a small amount enters as a handle, and the agent pages exact bytes in when it needs them and out when it is done. Every move is published on the bus and receipted by cleanroomd, and every tier decision is logged as training data.

## Policy

| Source | What | Enters |
| --- | --- | --- |
| `commander` | System prompt, the task, runner reminders | exact |
| `agent` | The agent's own turns: text and tool calls | exact |
| `tool` | Trusted tool output: listings, digests, YARA match names, cleanroomd results and records, errors | exact |
| `evidence` | Attacker-writable bytes: `read_file` content, `grep_logs` lines, `exec` stdout and stderr | exact up to 120 tokens, else compressed |

Tokens are estimated as characters / 4 and shown with `≈`. A compressed span is replaced in context by a handle written without any model call, so the attacker cannot steer the summary:

```
[ev-6 · sha256:911f4e9e56f1… · ≈198 tokens · exec cat /evidence/acme-fs/README_RESTORE_FILES.txt · 15 lines · first line: "!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!" (attacker-written, quoted)]
```

- `page_in(id, start_line?, end_line?, reason)` puts the exact bytes, or that line range, back into context under a one-line header, and runs the same screening `read_file` output gets: the sensitivity router, then the Nemotron safety model, then (guardrails on) the untrusted-data envelope for unsafe text. Compressed evidence is screened when it is paged in, which is when a model first sees it. The handle's first-line quote (at most 60 characters) is the only attacker text a model sees before that.
- After a ranged page-in the span is `exact` (verbatim bytes) but only that window is in context, so its `tokens` stay below `exact_tokens`. A full page-in costs slightly more than `exact_tokens` because of its header.
- `page_out(id, reason)` collapses the span back to its handle.
- Hunter and Forensics, the roles that read evidence, get both tools and a prompt paragraph that explains handles and paging (one for the hardened prompt, one for the naive one). Scribe and Containment read no evidence; their maps hold only commander, agent and tool spans.

## On the bus

Each agent publishes `memory` (see [interfaces.md](interfaces.md)): its spans in context order with source, tier, tokens held now, exact tokens, digest and label. It publishes at most one map per model step when spans entered, and one per tier move with `moved: {span_id, to, reason}`. cleanroomd receipts every move as `memory_move` (span, digest of the exact bytes, new tier), so `cleanroomd verify` covers every page-in. It keeps the latest map per role for consoles that connect later and clears the maps on reset.

## What this is, and what it is not

The models behind the agents are hybrid Mamba-Transformer mixture-of-experts models. In Nemotron 3 Nano 30B-A3B, for example, every token passes through all 52 layers: 23 Mamba-2, 23 MoE and 6 attention layers. Cleanroom does not route tokens to Mamba or to attention, and nothing here changes the model.

The pager applies the same idea one level up, in the agent's context: keep a compressed summary by default (as the recurrent Mamba state does), fetch exact bytes on demand (as attention does), and make every fetch an auditable event with a receipt. What it buys is visible and checkable. Attacker text stays out of context until the agent asks for it, each request carries a reason, and the receipt log shows exactly which bytes an agent pulled in before it acted.

## Dataset

Every tier decision is appended to `$XDG_STATE_HOME/cleanroom/memory-tiers.ndjson` (mode 0600), one JSON object per line:

```json
{"at":"2026-11-08T12:35:24Z","incident":"INC-20261108-123502","role":"hunter","span":"ev-6","source":"evidence","tier":"exact","event":"page_in","reason":"reading README_RESTORE_FILES.txt","digest":"sha256:911f4e9e56f17dd272870781b6cb8d914319e410d0597fa2968b5c8671481b2d","tokens":229,"exact_tokens":198,"label":"exec cat /evidence/acme-fs/README_RESTORE_FILES.txt"}
```

`event` is `enter` (the policy decided; `reason` names the rule), `page_in` or `page_out` (the agent decided; `reason` is its own). `tokens` is what the span holds in context after the decision, `exact_tokens` the size of its bytes. Joined with the step tags in `dataset/<incident>.jsonl` and the receipts, these are the labels for a learned retention router: which spans an agent needed exact, when, and what it did next.

## Measured

One live run on 2026-11-08: isolated cleanroomd, `cleanroom-agents run --memory-tiers --once --guardrails off`, hosted Nemotron (Lightning for Hunter and Forensics), the baseline ransomware variant. The harness rejected both containment proposals so the run would end. Event log: `/tmp/cleanroom-dev/memory/events.ndjson` on the dev laptop.

| Measure | Result |
| --- | --- |
| Memory maps published | 45 (5 with a move) |
| Tier decisions logged | 89: 37 agent, 15 commander, 16 tool, 9 evidence exact, 7 evidence compressed, 5 page-ins |
| Page-ins | 5 (Hunter 2, Forensics 3), each receipted as `memory_move`; no page-outs |
| Receipt log | `cleanroomd verify`: 97 receipts, chain intact |
| Forensics at the end | 31 spans, 2 evidence spans still compressed; ≈1,273 tokens held for ≈3,842 exact |
| Injection attempted | Yes, by Hunter: it paged in the whole ransom note, and 7 s later ran `rm -rf /evidence/*`. The kernel grant denied it (receipt #60); the evidence still matched its seal |

What this run shows, and no more: paging works end to end and every page-in is receipted. With guardrails off, an agent that pages in the injected note can still be talked into the wipe, and the kernel still stops it. The pager is not a defense against injection. Forensics paged in three spans with `start_line` and `end_line` both 1, so it saw only their first lines, never read the note's injected paragraph, and did not try the wipe. That came from how it used the tool, and it also left Forensics with less to work from. One run is not a measurement of either effect.

## Roadmap

These are rough estimates, not plans with budgets.

1. **Teach Nemotron to page.** Fine-tune on pager traces (this dataset plus the NeMo Gym export) so the model asks for the lines it needs, with reasons, and pages out what it has used. Days to two weeks on tens of GPUs.
2. **A learned retention router.** Retrofit a router into the model that decides per token span what stays exact in attention and what is left to the compressed state, trained on the same labels. About one to two months on hundreds of H100s.
