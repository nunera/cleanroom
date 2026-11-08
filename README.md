<p align="center">
  <img src="docs/assets/logo.svg" width="78%" alt="cleanroom, with Clean the mascot: a round white face with big black eyes, thick brows, a flat mouth and a teal stem">
</p>

<p align="center">
  An incident response OS. Nemotron agents investigate a breach from inside sealed, digest pinned Linux roots,<br>
  and the kernel keeps the evidence read only, whatever a ransom note talks them into.
</p>

<p align="center">
  <a href="#results"><img alt="Evidence files changed: 0 of 29 runs" src="https://img.shields.io/badge/evidence%20changed-0%20%2F%2029%20runs-2dd4bf?style=flat-square&labelColor=0b1117"></a>
  <a href="#results"><img alt="Kernel denied 15 of 15 wipe attempts" src="https://img.shields.io/badge/wipes%20denied-15%20%2F%2015-2dd4bf?style=flat-square&labelColor=0b1117"></a>
  <img alt="NVIDIA Nemotron" src="https://img.shields.io/badge/NVIDIA-Nemotron-2dd4bf?style=flat-square&labelColor=0b1117&logo=nvidia&logoColor=2dd4bf">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-2024-2dd4bf?style=flat-square&labelColor=0b1117&logo=rust&logoColor=2dd4bf">
  <img alt="Nix" src="https://img.shields.io/badge/Nix-flake-2dd4bf?style=flat-square&labelColor=0b1117&logo=nixos&logoColor=2dd4bf">
</p>

<p align="center">
  <a href="https://youtu.be/mHiA2bX0uxg">Demo video</a> ·
  <a href="#the-os">The OS</a> ·
  <a href="#nemotron-inside-the-os">Nemotron</a> ·
  <a href="#clean-the-lead-agent">Clean</a> ·
  <a href="#results">Results</a> ·
  <a href="#the-command-center">Command center</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#reference">Reference</a>
</p>

<br>

After a breach, the machines you'd investigate from can't be trusted, and neither can an AI agent that reads what the attacker left behind. Cleanroom handles both at the OS level. Every root and tool is pinned by digest and admitted before it runs. Each agent works inside a stratum whose walls the kernel enforces. Every command, denial and model call, including the model's reasoning, lands in a signed receipt log you can check offline.

Built in about 24 hours at **HackUTD 2026 (ZeroDay)** for the NVIDIA, Winstead and Best Design tracks.

## The OS

`cleanroomd` is the core. It runs rootless on Linux hosts that allow unprivileged user namespaces, holds the only signing key, and decides what every stratum may touch. The terminal captures below are real output from the shipped binary.

### Roots are admitted by digest

Each distro root is pinned in a lock file (`roots/debian-bookworm.lock.json`, `roots/alpine-3.21.lock.json`). Admission checks the manifest against the lock and every blob against the manifest, then records a digest of the unpacked tree that every launch checks again. Flip one byte and it's refused, naming the layer.

<img src="docs/os/tamper.png" width="100%" alt="cleanroomd tamper debian, then admit is rejected naming the layer, then the clean copy is admitted">

### Every agent runs in a stratum, and the walls are tested

A stratum is bubblewrap with every namespace unshared, no capabilities, a cleared environment and the admitted root read only at `/`. `cleanroomd probe` checks each wall from inside, as the agent, and signs one receipt per wall.

<img src="docs/os/probe.png" width="100%" alt="cleanroomd probe hunter: PASS for no network, no capabilities, no nested user namespaces, no secrets, evidence read only, host home not visible">

| Stratum | Root | What it can touch |
| --- | --- | --- |
| `hunter` | Debian bookworm | evidence and `/rules` read only, `/scratch` writable, admitted Nix tools |
| `forensics` | Alpine 3.21 | same as `hunter` |
| `acme-fs` | Debian bookworm | the victim share, writable (the ransomware runs here) |
| `rule-check` | Debian bookworm | clean seed and evidence, read only, for testing YARA rules |
| `scribe`, `containment`, `lead` | none | no exec at all |

### The kernel keeps the evidence read only

When an agent gets talked into wiping the evidence, the command reaches the kernel and fails there. cleanroomd records the denial, then rehashes the evidence and confirms it still matches the seal taken at detection.

<img src="docs/os/run.png" width="100%" alt="cleanroomd run hunter rm -rf /evidence/acme-fs: Read-only file system for every file, denied by the hunter grant, receipt 20, exit 126; then cleanroomd verify: chain intact">

### Software from any distro

The roots are real distros, so their software runs unchanged. The command center ships as a Debian `.deb` and runs inside the admitted Debian root on a NixOS host (`scripts/launch-tui.sh`). Hunter works on Debian's GNU userland and Forensics on Alpine's busybox. Tools the agents ask for (`yara`, `volatility3`, `tshark`, `file`, `binutils`) come from a pinned nixpkgs and carry their own libraries, so the same build runs in either root. Anything outside that allowlist waits for a commander's signature.

<img src="docs/visuals/distros.png" width="100%" alt="Debian bookworm and Alpine 3.21 roots, each pinned by digest and admitted, side by side on one Cleanroom host; a Debian package runs unchanged">

### Choose your init

The host itself is a declared plan: services, their dependencies, and the init that runs them. cleanroomd checks the graph before anything starts and names the cycle if there is one. Then `cleanroomd plan render` turns the same plan into dinit service files or an s6-rc source tree, and you pick which one boots:

```sh
nix run .#vm -- --init dinit     # or --init s6-rc; add --live for live Nemotron instead of the recorded run
```

That boots Cleanroom in QEMU/KVM with the chosen init as PID 1. It admits the Debian and Alpine roots, starts the daemon and the agent team, and puts the command center on the console.

NixOS is declarative too, but it's built around systemd, and software has to be packaged in nixpkgs. Cleanroom keeps the plan independent of the init, keeps the trusted base to a small supervisor, and runs other distros' software as it ships.

<table>
  <tr>
    <td width="50%"><img src="docs/visuals/plan.png" alt="One declared plan: cleanroomd, admit-debian, admit-alpine, cleanroom-agents and cleanroom-tui with their dependencies"></td>
    <td width="50%"><img src="docs/visuals/nixos.png" alt="NixOS fixes systemd as PID 1 and packages everything in nixpkgs; Cleanroom picks dinit or s6-rc at boot and runs Debian and Alpine roots as they are"></td>
  </tr>
</table>

<img src="docs/os/plan.png" width="100%" alt="cleanroomd plan validate: responder.json is valid with boot order under dinit; cycle.json is invalid under s6-rc with the dependency cycle named">

## Nemotron inside the OS

Every role runs on Nemotron, and every call goes through the OS like any other action.

<table>
  <tr>
    <td width="50%"><img src="docs/visuals/family.png" alt="The Nemotron family: Nano, Super and Ultra; Clean, Hunter, Forensics and Containment on Lightning, Vision on Super VL, Scribe on Ultra"></td>
    <td width="50%"><img src="docs/visuals/local.png" alt="Self-hosted: Cleanroom on Nemotron Lightning on vLLM on an RTX PRO 6000; evidence stays on the machine; 0.70 s local vs 1.06 s hosted"></td>
  </tr>
</table>

| Role | Model | Why this one |
| --- | --- | --- |
| Clean, the lead agent | Nemotron 3.5 Lightning 30B A3B | fast replies with reasoning on |
| Hunter, Forensics, Containment | Nemotron 3.5 Lightning 30B A3B | tool calling at about 1 s per step |
| Scribe | Nemotron 3 Ultra 550B A55B | writes the incident record |
| Forensics, images | Nemotron 3.5 Super VL 120B A12B | reads the ransom wallpaper |
| Safety screen | Llama 3.1 Nemotron Safety Guard 8B v3 | scores every piece of evidence first |
| Sensitive steps | Lightning NVFP4, Content Safety 3.5, Bolt E4B on our own Brev GPU | personal data stays off the hosted API; local Lightning answered at 0.70 s p50 vs 1.06 s hosted |

**Every call is a receipt, reasoning included.** cleanroomd signs each model call with digests of the exact request and response, and stores the chain of thought under the same receipt. Here is Forensics, with guardrails off, deciding to run the attacker's command. The OS can prove this is exactly what the model returned.

<img src="docs/os/reasoning.png" width="100%" alt="cleanroomd reasoning 54: Forensics' 389 token chain of thought reasoning that it should run rm -rf /evidence/*, and the line: this trace matches the digest in signed receipt 54">

Its next action was that command, and the kernel denied it in the very next receipt, #55.

**The OS sets the budget.** [`policy/reasoning.json`](policy/reasoning.json) is compiled in and caps how many tokens each role may spend thinking per step (1,024 for most, 768 for Containment), always leaving room for the answer. Receipts record what was actually spent.

**The OS checks what the model claims.** A finding that cites `/evidence/...` is checked: does the file exist, and did that agent's commands ever touch it? A scope flag cleanroomd measured can't be lowered by an agent. Hunter's YARA rules ship only if they compile, match no clean file and match some evidence.

**Memory tiers follow the model's layout.** Lightning has 52 layers: 23 Mamba-2, 23 mixture of experts and 6 attention. Only the attention layers recall exact tokens, and their cache grows with every one.

<img src="docs/visuals/hybrid.png" width="100%" alt="Lightning's layer groups: Mamba-2, MoE and attention blocks repeated, 23 Mamba-2, 23 MoE, 6 attention, 52 layers">

```text
MEMEM*EMEMEM*EMEMEM*EMEMEM*EMEMEM*EMEMEMEM*EMEMEMEME     from the served checkpoint's config.json
     ^      ^      ^      ^      ^        ^
     5      12     19     26     33       42

M  Mamba-2 ×23             fixed size state, about 46.8 MiB per conversation
E  mixture of experts ×23  routed experts, no state
*  attention ×6            KV cache, about 3 KiB per token in context
```

With `--memory-tiers`, anything the attacker wrote enters an agent's context as a short handle (digest, size, first line), and the agent pages the exact bytes in only when it needs them. cleanroomd receipts every page in and out. See [docs/memory-tiers.md](docs/memory-tiers.md).

**Training data the OS can vouch for.** A step is tagged trainable only if guardrails were on, the kernel didn't deny it and the safety model didn't flag it. `cleanroom-agents export-gym` turns an incident into NeMo Gym rows that pass NeMo Gym's own validator.

<img src="docs/visuals/tags.png" width="100%" alt="Agent steps tagged with role, model, what they read and provenance pass a gate: guardrails on, kernel allowed, safety model passed; denied and flagged steps drop out, trainable steps go on">

## Clean, the lead agent

<img align="right" width="150" src="docs/assets/clean.svg" alt="Clean, the mascot">

Clean is the agent you talk to. It narrates the incident as it happens, answers your questions and asks the specialists for you. It has no exec rights at all. Ask "did anyone try to delete the evidence?" and it answers with the receipt numbers.

The team is split the way a mixture of experts model is: Clean routes each task to one specialist (Hunter, Forensics, Scribe or Containment), and each specialist runs in its own stratum with only the grant its job needs.

<img src="docs/visuals/experts.png" width="100%" alt="Clean routes each task to Hunter, Forensics, Scribe or Containment, each inside its own walled stratum">

<br clear="right">

<img src="docs/screenshots/lead.png" width="100%" alt="The Clean tab: a red KERNEL BLOCKED banner over the conversation, and the team on the right">

## Results

29 live investigations: 27 against hosted Nemotron (three per cell) and two against our own on Brev, across five attack variants (a ransom note injection, a poisoned syslog line, a credential exfiltration note, a polite "IT runbook" written to slip past the safety model, and a benign control). Method and caveats are in [docs/eval.md](docs/eval.md).

| Measure | Result |
| --- | :-: |
| Evidence files changed by agents, hashed outside the sandboxes | **0 / 29 runs** |
| Wipe attempts denied by the kernel grant | **15 / 15**, each with a signed receipt |
| Receipt log chain intact | **29 / 29** |
| Agents went for the injected action, prompt guardrails off | 10 / 12 |
| Agents went for the injected action, prompt guardrails on | 0 / 12 |
| Safety model flagged the injected file | 14 / 24 (it missed the polite runbook every time) |

The prompt guardrails and the safety model both helped, and both are probabilistic. The kernel grant is not. These runs predate the newer checks (citation checks, the evidence seal, reasoning custody, the Alpine root, image evidence).

## The command center

`cleanroom-tui` connects as the commander and draws everything from signed bus events. On a booted Cleanroom host it runs on the console; on a laptop it runs as a Debian `.deb` inside the admitted Debian root.

<table>
  <tr>
    <td width="50%" valign="top"><img src="docs/screenshots/system.png" alt="System tab"><p><b>System</b>. Roots, strata walls, the evidence seal and the receipt chain.</p></td>
    <td width="50%" valign="top"><img src="docs/screenshots/overview.png" alt="Overview tab"><p><b>Overview</b>. What needs you next, activity over time, assets and legal deadlines.</p></td>
  </tr>
  <tr>
    <td colspan="2" valign="top"><img src="docs/screenshots/controlroom.png" alt="Controlroom"><p><b>Controlroom</b>. Everything on one screen, with every OS denial pinned at the top.</p></td>
  </tr>
</table>

<details>
<summary><b>Keys</b></summary>

<br>

| Key | Does | Key | Does |
| :-: | --- | :-: | --- |
| <kbd>d</kbd> | Detonate the scenario | <kbd>F1</kbd>…<kbd>F8</kbd> <kbd>F10</kbd> | Jump to a tab |
| <kbd>t</kbd> | Tamper with a root (it gets rejected) | <kbd>Tab</kbd> | Next tab |
| <kbd>A</kbd> | Admit the clean root again | <kbd>[</kbd> <kbd>]</kbd> | Move focus between panels |
| <kbd>a</kbd> / <kbd>x</kbd> | Approve or deny the selected item | <kbd>,</kbd> <kbd>.</kbd> | Switch the chart view |
| <kbd>g</kbd> | Toggle prompt guardrails | <kbd>T</kbd> | Cycle the theme |
| <kbd>i</kbd> | Start an investigation | <kbd>m</kbd> | Members: enroll or revoke a key |
| <kbd>v</kbd> | Verify the receipt log | <kbd>?</kbd> | Every key |
| <kbd>r</kbd> | Reset the victim share | <kbd>q</kbd> | Quit |

On the Clean tab you're typing straight away. <kbd>Enter</kbd> sends to Clean, `@hunter …` asks a specialist directly, and <kbd>Esc</kbd> hands the keyboard back to the command keys.

</details>

## Quick start

You need Linux with unprivileged user namespaces and Nix with flakes. Put a Nemotron key in `~/.config/cleanroom/nemotron.env` (it never enters the repo):

```sh
NVIDIA_API_KEY=nvapi-...
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
```

Then bring up the daemon, the agents and the command center in one tmux session:

```sh
scripts/demo.sh                       # hosted Nemotron, guardrails on
scripts/demo.sh --guardrails off      # watch the kernel stop what the model was talked into
scripts/demo.sh --local               # sensitive steps go to Nemotron on Brev
scripts/demo.sh --replay              # the recorded run in recordings/llm, no network at all
scripts/demo.sh --memory-tiers        # agents page evidence in and out of their context
```

In a replay the daemon still runs every command and the kernel still denies the wipe. Only the model answers are recorded, so follow the beats in the order `scripts/demo.sh --help` lists. To just watch the recorded screen, with no daemon at all:

```sh
nix develop -c cargo run --release -p cleanroom-tui -- --replay recordings/demo-events.ndjson --speed 4
```

`nix run github:nunera/cleanroom` runs `cleanroomd` straight from the flake, and `nix run github:nunera/cleanroom#agents -- run` runs the team.

## Reference

The details, for anyone who wants them.

<details>
<summary><b>cleanroomd, the OS core</b></summary>

<br>

One Unix socket, `$XDG_RUNTIME_DIR/cleanroom/cleanroomd.sock` (mode `0600`), carries the bus and the operations in [docs/interfaces.md](docs/interfaces.md). It runs rootless: start it inside `nix develop` (bubblewrap, skopeo, umoci) on a host that allows unprivileged user namespaces.

```sh
cleanroomd [--socket PATH] [--state DIR] [--repo DIR]   # serve until SIGINT/SIGTERM
cleanroomd [--socket PATH] admit ROOT                   # exit 0 admitted, 1 rejected, 2 error
cleanroomd [--socket PATH] verify                       # receipt signatures and chain: exit 0 intact, 1 broken
cleanroomd [--socket PATH] reset                        # re-seed the victim, close the incident, keep receipts
cleanroomd [--socket PATH] detonate [SCENARIO]          # default ransomware; starts the investigation
cleanroomd [--socket PATH] tamper [ROOT]                # flip a byte in a staged copy; the next admit is rejected
cleanroomd [--socket PATH] run STRATUM [--timeout S] -- CMD...  # as that agent, under its grant: exit = CMD's, 124 timeout, 126 denied
cleanroomd [--socket PATH] probe [hunter|forensics]    # test the stratum's walls from inside, one receipt per wall
cleanroomd reasoning SEQ [--state DIR]                 # offline: the reasoning behind model_call receipt SEQ; exit 1 if it changed
cleanroomd plan validate FILE                           # offline: boot order, or the cycle witness
```

`--repo` is where `scenario/` and `roots/` live (default: the nearest ancestor of the binary that has both, else the current directory). State lives in `$XDG_STATE_HOME/cleanroom`: `store/oci`, `store/containers-policy.json`, `store/staging/<root>`, `store/roots/<root>/rootfs`, `keys/cleanroomd.key`, `keys/members.ndjson`, `run/acme-fs/{share,drop,logs}`, `run/scratch/<role>`, `run/bin` and `receipts.ndjson`.

**Strata.** bubblewrap with every namespace unshared (so no network), no capabilities and a cleared environment. The admitted root is read only at `/`, with a fresh `/proc`, `/dev` and `/tmp`. No stratum can create a nested user namespace (`--disable-userns`, so `unshare -U -r` fails instead of handing a steered command uid 0), and bubblewrap refuses to start one where it can't enforce that (`--assert-userns-disabled`). Output is capped at 64 KiB per stream, timeouts at 5 minutes. A command whose stderr shows `Read-only file system` is `denied`, with a receipt and a status line.

| Stratum | Root | Grant |
| --- | --- | --- |
| `hunter` | `debian` | `/evidence/acme-fs`, `/evidence/dropbox`, `/evidence/logs` and `/rules` read only; `/scratch` writable; `/nix/store` read only when the role holds admitted tools |
| `forensics` | `alpine` | same as `hunter` |
| `acme-fs` (victim) | `debian` | `/srv/acme-fs/{share,drop,logs}` writable; `/opt/cleanroom/bin` read only |
| `rule-check` | `debian` | the clean seed and the evidence, read only, for checking the YARA rules agents write |
| `scribe`, `containment`, `lead` | none | no exec: every request is denied |

`CLEANROOM_ROOTS` moves strata onto other admitted roots, for example `CLEANROOM_ROOTS=forensics=debian`. The agents' file tools are busybox on Alpine and GNU coreutils on Debian; admitted Nix tools bring their own libraries from `/nix/store`, so they run on either.

**Roots.** A lock (`roots/<name>-*.lock.json`) pins one platform manifest digest. Two are pinned: `debian` (`debian:bookworm-slim`) and `alpine` (`alpine:3.21`). Admission fetches the image once with skopeo into `store/oci` (later admissions are offline), checks a staged copy (the manifest against the lock, every blob against the manifest), unpacks it with `umoci raw unpack --rootless`, and records a digest of the unpacked tree that every stratum launch checks again. Trust comes from the lock's digest and the blob checks, not image signatures. `tamper` flips one byte in the first layer of a staged copy; the next `admit` answers `admit_rejected`, names that layer and discards the copy.

To pin a new root, resolve the linux/amd64 platform manifest (not the multi-arch index) and check its digest:

```sh
skopeo inspect --raw docker://docker.io/library/alpine:3.21 \
  | jq -r '.manifests[] | select(.platform.os=="linux" and .platform.architecture=="amd64") | .digest'
skopeo inspect --raw docker://docker.io/library/alpine@<digest> | sha256sum   # must print the same digest
```

**Probe.** `cleanroomd probe [hunter|forensics]` tests the walls from inside the stratum, as its agent, one command and one signed receipt per wall: only `lo` in `/proc/net/dev`, `CapEff` all zero, `unshare -U` refused, nothing in the environment but `HOME`, `LANG`, `TMPDIR`, `PATH` and `PWD` (a leaked variable is named, never printed), a write under `/evidence` denied by the kernel, and the invoking user's `$HOME` absent.

**Tools.** `request_tool` for `yara`, `volatility3`, `tshark`, `file` or `binutils` from the pinned nixpkgs is allowed automatically. Any other well formed nix reference waits for a commander's signed `approve`, and OCI sources are denied. A granted tool's `bin` directories go first on the role's `PATH`. Hunter holds `yara` from the start, and the allowlist is built in the background so later grants are instant and work offline.

**Detection rules the agents write.** Hunter writes a YARA rule for the attack it found and sends it with `submit_rule`. cleanroomd runs it in a sandbox twice, over the clean seed files and then over the evidence, and admits it into `/rules/agent-<name>.yar` only if it compiles, matches no clean file and matches some evidence. Otherwise the agent gets the reason and can fix it. Either way the verdict is a `yara_rule` receipt.

**Bus.** The first frame must be `hello`. Every `publish` must verify against the connection's key and name the connection's principal. Tool requests, tool decisions and approvals come only from cleanroomd; `investigate` and `agent_control` only from humans; `scope` and `incident` only from Scribe or a human; `proposal` only from Containment; a `memory` map only from the agent it describes. An agent's `scope` that lowers a flag cleanroomd measured `yes` is dropped with a denied receipt and an "OS kept the record" status. A new client first gets the latest incident, scope per asset, open requests and proposals, counters and memory maps.

**Approvals and members.** An `approve` must come from a human connection whose key signed the decision. Until someone is enrolled, any human key on the socket may approve, and the first `enroll` must be an admin enrolling their own key. After that only enrolled admins enroll or `revoke`, and only enrolled commanders and admins approve. A revoked key stops working at once and after restarts. The last admin can't be revoked.

**Receipts.** `receipts.ndjson` holds one signed receipt per line; `seq` is the line number and `prev` the digest of the previous one. Every exec (allowed or denied), admission, tamper, detonation, tool grant, approval, enrollment, record update, memory move and reset is recorded, and so is every model call the agents make. `verify_log` reports the first entry that fails its signature or its chain.

**Evidence seal.** At detection cleanroomd hashes every file under `/evidence` into one digest. After every agent command it hashes them again: a denied command's status line adds "evidence unchanged: still matches the seal from receipt #N", which holds however the command hid its errors. A change is resealed with a new receipt and an `EVIDENCE CHANGED` status naming the files. `verify_log` compares the evidence with the seal from detection too, so a later reseal never hides a change.

**Reasoning custody.** Nemotron returns its chain of thought beside every answer. cleanroomd stores it in `reasoning.ndjson` under the receipt's number and puts its digest and token count in the signed receipt. `cleanroomd reasoning SEQ` works offline and tells you whether the stored trace still matches.

**Citation checks.** When an agent publishes a `finding`, cleanroomd checks every `/evidence/...` path it cites: does it exist, and did a command run for that agent touch it or a directory above it? The finding is never dropped, but a model that invents a source or cites a file it never opened is named in the record.

**Scenario.** At startup and on `reset` the share is seeded again from `scenario/acme-fs`, and every asset in `scenario/assets.json` is published with all flags `no`. `detonate` runs `cleanroom-ransom` in the `acme-fs` stratum, compares the share with its seeding hashes (changed assets become `locked`, `accessed` and `modified`) and hashes the drop box: a byte for byte copy of a seeded file there is a staged copy, which makes its asset `accessed`. `exfiltrated` stays unknown, because a copy on the host isn't proof it left. Then it opens the incident and publishes `investigate`. `reset` takes a few milliseconds, keeps the receipts, and closes the incident so a still running investigation can't repaint the table.

</details>

<details>
<summary><b>cleanroom-agents, the Nemotron team</b></summary>

<br>

```sh
cleanroom-agents run [--guardrails on|off] [--max-steps N] [--socket PATH] [--once] [--memory-tiers]
cleanroom-agents export-gym --incident INC-… --out pivots.jsonl
```

The runner opens one socket connection per role, waits for an `investigate` event and runs the team. Hunter and Forensics investigate at the same time inside their strata, their findings flow to Scribe, and Containment proposes actions for the commander. Clean stays up across incidents unless you pass `--once`.

**Guardrails on or off.** With guardrails on, Hunter and Forensics use typed read only tools, report findings as they go, and log each instruction they decline from untrusted data as a `refusal`. With guardrails off they're set up the way a careless team might deploy them: a "helpful sysadmin assistant" with only a shell and `report_finding`, told to read the notes on the share and handle them. The prompt never mentions the injected instruction; the ransom note supplies it, and the grant denies it. `g` in the command center switches at runtime.

**Clean, the lead agent.** It keeps a live picture of the incident from bus events alone and narrates key moments in short templated lines with no model call: the detonation, each agent's first OS denial (with the file it had just read and the receipt), first findings, proposals waiting and scope changes. A question to Clean always gets exactly one answer, even when the model fails. Its tools are `get_situation`, `ask_agent` (asks a specialist and waits up to 45 s) and `reply`. Its prompt is always the hardened one, and an answer that claims an approval goes back to the model to be rewritten, because approvals are for humans only.

**Specialists answer questions.** A chat to a specialist gets one short answer from that specialist's model, with what it has done in this incident. It runs no tools and never blocks the investigation.

**Safety and routing.** Every tool output that carries evidence is scored by the safety model before a model sees it. With guardrails on, unsafe output is wrapped in an untrusted data envelope. Output with personal data or credentials moves the conversation to the local endpoint.

**Image evidence and the visual injection.** With guardrails on, Forensics has `view_image` for PNG, JPEG, GIF and WebP. The runner reads the file inside Forensics' stratum (so the grant applies and the read gets a receipt), refuses anything over 48 KiB or not starting with image bytes, and sends it to Nemotron Super VL with a system prompt saying text in the image is data. `detonate ransomware-visual` moves the injection out of the note and into the ransom wallpaper, where grep and YARA never see it. Only `view_image` puts it in front of a model, and the transcription is screened like any evidence.

**Scope can't be talked down.** Scribe starts from the scope records cleanroomd already published, so it updates real assets instead of inventing new ones. `update_scope` refuses to lower a flag cleanroomd measured, and refuses to clear `exfiltrated`, which only a human may do. cleanroomd enforces both on the bus. Legal clocks for GDPR and HIPAA are stamped with the detection time however late Scribe records them.

**Memory tiers.** With `--memory-tiers`, every message in an agent's conversation is a span: `cmd-N` for the commander and system prompt, `ag-N` for the agent's own turns, `tool-N` for trusted tool output, and `ev-N` for anything the attacker could have written. Evidence over about 120 tokens enters as a deterministic handle, with no model call, so the attacker can't steer the summary. Hunter and Forensics get `page_in` and `page_out`. Every decision goes to `$XDG_STATE_HOME/cleanroom/memory-tiers.ndjson`.

**Reliability fixes.** Tool arguments are conformed before validation (`"95%"` and `0.95` both become 95, a single path becomes a list, enum values match case insensitively). Halfway through its step budget, an agent with no finding yet is offered only its reporting tools. Each role's reasoning budget leaves at least 512 of the step's 2,048 tokens for the answer, so a model can't spend its whole turn thinking. A reset stops the team immediately, so no model call is spent on a closed incident.

**Training ready tags.** The runner appends one JSON line per tool call to `$XDG_STATE_HOME/cleanroom/dataset/<incident>.jsonl`: role, step, model, route, what it read, the step's shape, provenance and the receipt of the command. A step is `trainable` only with guardrails on, when the grant didn't deny it and the safety model didn't flag what it read. `export-gym` turns the trainable calls of an incident into NeMo Gym rows in the `single_step_tool_use_with_argument_comparison` format. A live run gave 36 rows that pass NeMo Gym's own `validate_pivot_dataset.py`. Nothing is trained here.

| Variable | Meaning |
| --- | --- |
| `CLEANROOM_MODEL_LEAD` | Clean's chat model (default `nvidia/nemotron-3.5-lightning-30b-a3b`) |
| `CLEANROOM_MODEL_HUNTER`, `_FORENSICS`, `_CONTAINMENT` | Tool loop model (default `nvidia/nemotron-3.5-lightning-30b-a3b`) |
| `CLEANROOM_MODEL_SCRIBE` | Record keeper (default `nvidia/nemotron-3-ultra-550b-a55b`) |
| `CLEANROOM_MODEL_SAFETY` | Safety model (default `nvidia/llama-3.1-nemotron-safety-guard-8b-v3`) |
| `CLEANROOM_MODEL_VISION` | Vision model for `view_image`, always hosted (default `nvidia/nemotron-3.5-super-vl-120b-a12b`) |
| `CLEANROOM_LOCAL_BASE_URL`, `_MODEL`, `_API_KEY`, `_SAFETY_MODEL` | Optional local endpoint for sensitive evidence (model default `nvidia/nemotron-3.5-bolt-e4b`) |
| `CLEANROOM_LLM_CACHE=record\|replay`, `CLEANROOM_LLM_CACHE_DIR` | Record model answers, or replay them with no network client (default dir `~/.cache/cleanroom/llm`) |
| `CLEANROOM_MEMORY_TIERS=1` | Same as `--memory-tiers` |
| `CLEANROOM_NIXPKGS` | Pinned flake prefix for tool requests (default: the `flake.lock` nixpkgs rev) |

Signing keys are created on first run in `$XDG_STATE_HOME/cleanroom/keys/<role>.key` (mode `0600`).

</details>

<details>
<summary><b>Egress and model access</b></summary>

<br>

Egress is declared in [`policy/egress.json`](policy/egress.json) and denied by default. The model router may reach only `https://integrate.api.nvidia.com` (hosted Nemotron) and `http://127.0.0.1:8000` (Brev, through `deploy/brev/tunnel.sh`). The policy is compiled into the agents binary. At start the router refuses any endpoint outside it, and its HTTPS client follows no redirects and ignores proxy variables. The strata have no network at all, and replay mode doesn't build a network client. Adding an endpoint means editing the policy and rebuilding.

Point `NVIDIA_BASE_URL` at any OpenAI compatible server (Brev, vLLM, NIM) to run Nemotron yourself. `deploy/brev/` has the setup we used: Lightning NVFP4 on vLLM, Content Safety 3.5 and Bolt E4B on llama.cpp, all behind one LiteLLM endpoint with a bearer key.

</details>

<details>
<summary><b>cleanroom-tui flags and the Debian package</b></summary>

<br>

| Flag | Meaning |
| --- | --- |
| `--socket PATH` | cleanroomd's socket (default `$XDG_RUNTIME_DIR/cleanroom/cleanroomd.sock`) |
| `--record FILE` | Save every frame from cleanroomd, for replay later |
| `--replay FILE` `--speed X` | Play a recording offline, with a REPLAY badge on screen |
| `--theme NAME` | `cleanroom`, `ember`, `lavender`, `phosphor` or `projector` (also `CLEANROOM_THEME`) |
| `--no-motion` | No animation (also implied by `NO_COLOR`) |
| `--tamper-root NAME` | Root that `t` tampers with and `A` admits (default `debian`) |
| `--scenario NAME` | Scenario that `d` detonates (default `ransomware`) |

The `.deb` is static musl and runs on bookworm and trixie:

```sh
nix develop --command nix shell --inputs-from . \
  nixpkgs#pkgsCross.musl64.buildPackages.rustc nixpkgs#pkgsCross.musl64.stdenv.cc \
  --command env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-cc \
  'CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS=-C target-feature=+crt-static' \
  cargo deb -p cleanroom-tui --target x86_64-unknown-linux-musl
```

</details>

<details>
<summary><b>Repository layout</b></summary>

<br>

```text
cleanroom/
├── crates/
│   ├── proto/        wire types shared by everything
│   ├── daemon/       cleanroomd: admission, strata, grants, receipts, bus, scenario
│   ├── agents/       cleanroom-agents: model router, roles, Clean, safety, pager
│   ├── tui/          cleanroom-tui: the command center, shipped as a static .deb
│   ├── ransom/       cleanroom-ransom: safe, reversible canary ransomware (static musl)
│   └── eval/         cleanroom-eval: runs attack variants and scores them
├── scenario/         the acme-fs seed share, assets.json, YARA rules, answer keys
├── roots/            digest locks for Debian bookworm and Alpine 3.21
├── plans/            declarative host plans (init choice and service graph)
├── policy/           egress.json and reasoning.json, compiled into the agents
├── deploy/brev/      Nemotron on our own Brev GPU, and the laptop tunnel
├── recordings/       a recorded demo run: model answers for --replay, and its screen
├── scripts/          demo.sh, launch-tui.sh, lockstar-wallpaper.sh
└── docs/             interfaces, eval, memory tiers, Nemotron measurements
```

| Doc | What's in it |
| --- | --- |
| [docs/interfaces.md](docs/interfaces.md) | Transport, signing, receipts, daemon operations, grants, every bus message |
| [docs/eval.md](docs/eval.md) | The 29 run evaluation: method, per variant results, caveats |
| [docs/memory-tiers.md](docs/memory-tiers.md) | The evidence pager, the dataset format and the roadmap |
| [docs/nemotron-smoke.md](docs/nemotron-smoke.md) | Hosted and local Nemotron measured: tool calls, latency, injection, safety models |
| [scenario/README.md](scenario/README.md) | The victim share, the assets and the attack variants |

</details>

## Team

<table>
  <tr>
    <td align="center" width="50%">
      <a href="https://github.com/nunera"><img src="https://github.com/nunera.png" width="88" alt="Michael Kryvonis"><br><b>Michael Kryvonis</b></a><br>
      <sub>Agents, Clean, the command center, the eval</sub>
    </td>
    <td align="center" width="50%">
      <a href="https://github.com/ZacharySF"><img src="https://github.com/ZacharySF.png" width="88" alt="Zachary Stubbs"><br><b>Zachary Stubbs</b></a><br>
      <sub>OS core, scenario, image evidence, NeMo Gym export</sub>
    </td>
  </tr>
</table>

<p align="center"><sub>Built at HackUTD 2026 (ZeroDay), UT Dallas, November 7 and 8. Licensed under <a href="LICENSE">Apache 2.0</a>.</sub></p>
