# NVIDIA / Nemotron track: what wins, what is novel (Nov 2026)

Written Sat 2026-11-07. Intended path: `/home/dreams/HackUTD/Tracks/research/criteria-nvidia.md`. Main must copy it.
Tags: **[V]** = I opened the source. **[SS]** = from a search-engine summary only, page not opened or not confirming. **[INFERENCE]** = my reasoning. **[UNVERIFIED]** = could not confirm.
Prior HackUTD winner research (`past-winners.md`) was not redone. Toyotron is summarized only for comparison.

## Key findings

1. **The specific idea has been done on this exact track.** SteelHacks XIII (Sep 19–20, 2026) NVIDIA "Beyond the Chatbot" had **Bouncer**, a Nemotron "intent firewall" that checks every MCP tool call against the user's goal and blocks prompt-injection hijacks [V: github.com/VirajMishra1/bouncer]. It also had **Nemotron Verifier**, a Nemotron gate for LLM output [V]. Bouncer was *entered*; whether either one *won* is [UNVERIFIED] (see §1). The HackUTD NVIDIA deck is a SteelHacks reuse, so the same NVIDIA staff may remember them.
2. **Plain "agent firewall vs prompt injection" is therefore seen-it-before. Interlock still has a real gap.** I found no NVIDIA-track project with (a) a *physical-plant* interlock, (b) *Ed25519 signed approvals and receipts*, (c) a *live audience attacking from phones*, or (d) a *tabletop rig where the valve physically does not open*. These are absence-of-evidence in my sample [INFERENCE], not proof of absence.
3. **Interlock matches NVIDIA's own Sep 28, 2026 safety thesis almost word for word.** "Enforcement must be out of band", "an agent cannot be expected to fully govern its own behavior", and "policy needs to be verifiable" appear in the *NVIDIA Open Agent Safety Platform* post [V]. This helps. The risk is that it looks like a reimplementation of OpenShell/NeMo Guardrails. Position it as the **domain-physics and signed-authority layer above them**.
4. **NVIDIA's own tool-call rail already does the "schema" layer.** NeMo Guardrails IORails has `tool call validation` (allowlist plus JSON-Schema, fail-closed, experimental) [V: docs.nvidia.com/nemo/guardrails/.../tool-calling]. Use it as layer 1 and call it out, rather than hand-rolling it silently.
5. **Judges reward evidence and a fast aha.** Nota AI won the NVIDIA-hosted Seoul hackathon with a quantified result when rivals showed flashy agent demos [V: blog.nota.ai]. Nebius×NVIDIA judges say "two minutes in the project, 30 seconds in the demo" [V: Devpost updates index]. Interlock needs a measured block-rate and false-block table and an ablation toggle (interlock OFF vs ON).
6. **Local/edge is a plus, not a requirement.** NVIDIA events pay in Jetson Orin Nano Super, DGX Spark and Brev credits, and TreeHacks had a dedicated Edge AI track [V]. But both 2025 HackUTD NVIDIA winners used hosted Nemotron (Toyotron via OpenRouter [V]; Alchemetrics unspecified [SS]). Running the *same open-weights model* locally as a fallback or toggle is on-message and cheap.
7. **HackUTD 2025's other NVIDIA winner (Alchemetrics) was an EOG-shaped problem.** It was tank/cauldron level forecasting plus transport-ticket reconciliation plus OR-Tools routing, with Nemotron as the planner [SS: devpost.com/software/abc-xapnio; page is 403 for me]. A forecast/dispatch console alone is the *baseline* the NVIDIA judges already rewarded. Interlock's safety layer must be visibly *additional*, and the agent must visibly do useful multi-step work first.
8. **Tool-calling quality is uneven in practice.** Teams report Nemotron Lightning timing out or truncating JSON on the hosted API (Bouncer README [V]) and 10–30 s tail latency on one call in three (Weave Devpost [V]). Plan for non-thinking mode, hedged requests, a fallback model, and a fail-closed path. Fail-closed is a feature to *show*.
9. **Use NVIDIA's safety models, but know what they cannot do.** Nemotron 3.5 Content Safety (4B, custom natural-language policy, think-mode traces, multimodal) [V] and NemoGuard JailbreakDetect [V] classify *content*. A physically unsafe valve command is not toxic content. The strongest on-screen story is [INFERENCE, must be tested live]: the NVIDIA classifier says SAFE and the physical interlock still says NO.
10. **Physical tabletop demos fit the pattern.** TreeHacks Edge track winners were a self-driving car on Jetson Thor (TORQ), a Jetson gantry microfarm (Sprout) and an on-device satellite agent (Detour) [V repos/Devpost]. UCSC NemoClaw winners included an autonomous hydroponics agent [V]. Available hardware (ESP32-S3, relays, water-level sensors) can make a miniature tank/valve rig. cuOpt is NVIDIA's own solver and won the 2025 NeMo hackathon [V]; using it for dispatch is on-brand [INFERENCE].

---

## 1. Winners and notable entries (2025–2026)

Prize and track context for HackUTD 2026: 1st = 2× RTX 5080 + $200 Brev, 2nd = 1× RTX 5080 + $200 Brev + swag; $60 Brev per Nemotron-track team; contact Ethan Einhorn [V: `sources/nvidia-hackutd26.pdf`, slides 2–4]. In 2025 the NVIDIA track had 103 teams [V: Retrograde].

### 1a. HackUTD 2025 (same event, previous year)

| Project | URL | What it did | Nemotron model / tools | Demo hook | Status |
|---|---|---|---|---|---|
| **Toyotron** (1st NVIDIA and 1st TFS) | https://devpost.com/software/toyotron | Multi-agent Toyota concierge: onboarding, search over 1,150 trims, finance calc, test-drive booking, trade-in valuation | Nemotron 49B via OpenRouter; Vercel AI SDK, Next.js, Supabase, Retell (real phone call), Resend, Google Calendar, NHTSA VIN API, GPT-4o Vision | A real phone call plus a calendar invite plus a VIN-decoded trade-in, live | [V] (prior research, Devpost page loaded); winner badge confirmed by [V] Retrograde https://retrogradenews.com/2025/12/08/hackutd-marks-ten-years-of-hackathons-with-fantasy-and-fire-alarms/ |
| **Alchemetrics** (NVIDIA winner) | https://devpost.com/software/abc-xapnio | "Poyo's Potion Factory" dashboard: detects drain events from cauldron-level sensors, reconciles transport tickets, forecasts overflow ETAs, plans courier routes | Nemotron as Planner agent over Event-Detection, Ticket-Matching, Discrepancy-Auditor, Forecasting and UI agents; FastAPI, SQLAlchemy, Google OR-Tools, Next.js | Map + timeline + live Nemotron reasoning log + audit tables | Page 403 for me. Details and winner status [SS]; "Winner, Nvidia" also in prior research's gallery snippet. Team: Ashrita Dara, Isha Rao, Joanne Ramesh [SS]. **[INFERENCE]** the level/drain/ticket structure mirrors the EOG saltwater-hauling problem, so this is a close precedent for EOG + NVIDIA. |

### 1b. SteelHacks XIII (Pitt, Sep 19–20, 2026): the track the HackUTD deck was reused from

Track: "[NVIDIA] Beyond the Chatbot", **3 winners**, each team gets 4× Jetson Orin Nano Super + 4× $50 Brev vouchers + 4 hats; 149 projects in the gallery; 452 participants [V: https://steelhacksxiii.devpost.com/]. The gallery exposes no winner badges in text [V], so **who won is [UNVERIFIED]**.

| Project | URL | What it did | Nemotron model / tools | Demo hook | Status |
|---|---|---|---|---|---|
| **Bouncer** | https://github.com/VirajMishra1/bouncer | Intent firewall between an agent (MCP client) and its tools. Checks each call against the user's stated goal; ALLOW / ASK / BLOCK; fails closed | Nemotron **Super** as judge; MCP proxy (TypeScript), eval harness (Python). Reports: 48-case self-authored set, Nemotron Super 93.8% accuracy, 100% attacks blocked, 87.5% benign allowed, p50 ≈ 1.05 s; AgentDojo replay of 100 public traces: 76.6% of injected actions stopped or escalated vs 21.3% for rules. Says Lightning was unreliable on the hosted API | 29-second video: same injected email, Bouncer OFF forwards the inbox, ON refuses. "Bouncer Live" page shows each tool call queueing at a door | [V] README. It states it was *entered* in the NVIDIA track and two others. A search summary calls it a winner [SS]: **[UNVERIFIED]**. Closest prior art to Interlock. |
| **Nemotron Verifier / Triage Model** | https://github.com/kyuhan28/nemotronverifier (and `/nemotrontriagemodel`) | Nemotron never answers the user. It triages intake and audits another model's draft health advice; a deterministic Python `gate()` with 8 rules decides | Nemotron 3 Super 120B-A12B (thinking off for routing, on for audit); Ultra 550B to corrupt drafts for evals; GPT-4o-mini as drafter | Live dropdown: switch the verifier to **None** and watch the unchecked output ship (ablation on stage). 43 labeled cases: 27/33 corrupted drafts caught (v1), 31/33 (v2) | [V] README ("SteelHacks XIII's Beyond the Chatbot Submission"). Winner status [UNVERIFIED]. Its core rule: "Never ask the model for a field you intend to act on mechanically. Ask for observations; compute decisions" (Interlock's thesis). |
| **Casefile** | https://github.com/RohanPejaver/steelhacks | Agent investigates a security alert by asking questions of logs, issues a verdict with cited log events | Nemotron picks the next question and decides when to stop | n/a | [SS] only |
| **Heard!** | https://devpost.com/software/heard-puhs0f | Ambient meeting copilot: live board of ideas, knows when to stay quiet, dispatches background research | Nemotron Super 120B (reasoning off) as utterance classifier plus a notes agent; Claude Agent SDK as the "front desk"; ElevenLabs Scribe v2 STT and TTS | Cards appear on a shared canvas within ~5 s of being spoken | Page 403 for me. Search summary says **1st place** in the NVIDIA track [SS]: **[UNVERIFIED]**. |
| **Weave** | https://devpost.com/software/weave-z8t1i0 | Co-browsing Electron browser: helper's cursor and lasso appear on the other person's page; per-person accessible rebuild; spider assistant "Webb" | **Nemotron 3.5 Lightning via NIM** for answers, element targeting and layout proposals; Gemini for translation; ElevenLabs | Helper circles the exact button on a grandparent's bank page | [V] Devpost page. No winner badge in the fetched text. A search summary lists it among winners [SS]: **[UNVERIFIED]**. Candid latency notes: see finding 8. |
| (name collision) **Interlock** | https://devpost.com/software/interlock-y8xneb | Pittsburgh street-change simulator (traffic, weather, autonomous vehicles) | n/a | n/a | [V] gallery tagline. Unrelated concept, but **same name**. A judge who was at SteelHacks could be confused; consider renaming. |

### 1c. Other 2025–2026 events (user's list)

| Event | NVIDIA / Nemotron track? | Winners found | Status |
|---|---|---|---|
| **TreeHacks 2026** (Stanford, Feb 14–15) | Yes: "[NVIDIA] Edge AI Track" (4 winners; 1st = DGX Spark + 2× $450 Brev + 2× Jetson Orin Nano Super) and "Open Models Hit Different on DGX Spark" (Jetson Orin Nano Super) [V: https://treehacks-2026.devpost.com/] | **TORQ** (repo says "Nvidia Edge AI Track 1st Place"): retrofit Honda with Jetson AGX Thor; Alpamayo R1 VLA (10.5B) for reasoning, sunnypilot control loop, SwiftUI hail-a-ride app that shows the AI's reasoning. **Not Nemotron.** [V: https://github.com/bryandong24/treehacks2026]. **Detour** (repo says "Honourable Mention Winner"): multi-agent satellite debris-avoidance; **Nemotron-3-Nano-30B-A3B-NVFP4** served by vLLM on an ASUS Ascent GX10 / DGX Spark, air-gapped; LangGraph; SGP4 etc. in deterministic Python; Planner and **Safety** agents check burns against fuel and burn limits; 3D globe plus agent terminal trace [V: https://devpost.com/software/detour-64kpds, https://github.com/keanucz/detour]. **Sprout**: Jetson Nano gantry microfarm [V Devpost; placement not shown]. **CalTrack**: disaster response [SS]. | Placements are team self-claims in their own repos [V]. A search summary named Detour as "the winner" and another named TORQ 1st [SS]; the repos reconcile this (TORQ 1st, Detour HM). Official gallery not readable. |
| **Cal Hacks 13.0** (Oct 23–25, 2026) | No dedicated Nemotron track found; sponsors listed as Anthropic, Annapurna, SpacetimeDB, Hyphenate, Fetch.ai, Microsoft, Supercell, Visa [SS: https://cal-hacks-13-0.devpost.com/] | None | [UNVERIFIED] absence. |
| **HackMIT 2026** | NVIDIA co-sponsored with ASUS: GX10 hardware for local agentic AI; sponsor challenge is the **ASUS Zenni Claw "Agent Computer Challenge"**, not a Nemotron-model track [V: https://www.asus.com/us/business/resources/news/asus-hackmit-2026/]. | A search summary lists CareChair (1st; robotic-caregiver wheelchair, on-device reasoning), Paw Patrol, Newton's Playground [SS] | Winners and any Nemotron use [UNVERIFIED]. |
| **MHacks 2026** (Oct 3–4) | No NVIDIA track found (sponsors incl. Photon, SpacetimeDB, ElevenLabs, Fetch.ai) [SS: https://mhacks-2026.devpost.com/] | None. MHacks 2025 had an NVIDIA Jetson prize, not a Nemotron track [SS]. | [UNVERIFIED] absence. |
| **NVIDIA GTC 2026 "Agents for Impact"** (Mar 19, SJSU, ~300 participants) | NVIDIA-hosted | **Loomin** (Preet Karia, UC Santa Cruz): type a physics concept, get notes, equations and an interactive 3D model; when you break the simulation it explains why. Nemotron **Ultra** plus RAG over a local physics knowledge base; <3 s. Winner met Jensen Huang. | [V: https://news.ucsc.edu/2026/04/engineering-student-wins-nvidia-agents-for-impact-hackathon/] |
| **Nemotron Developer Days Seoul** (Apr 21–22, NVIDIA's first Korean hackathon, 20 teams) | NVIDIA-hosted; Track A Creative Agentic Systems, B Domain-Specific Models, C Synthetic Data | **Nota AI** (Grand Prize + Track C): agent on **Nemotron 3 Super** that generates calibration data to wake rarely-used MoE experts for better quantization. Judges' stated reason: "not only qualitative but also quantitative evaluation" while others showed polished agent demos. Peer vote = 20 points. Prize: DGX Spark. **NAVER** won Track A. | [V: https://blog.nota.ai/insights/nemotron-hackathon-winner]. Winning pitch: 5 min, GitHub demo behind a QR code, one-liner joke pointing at the DGX Spark. |
| **NemoClaw / Hack-a-Claw @ UCSC** (May 15–16, NVIDIA + ASUS, 200+ students, DGX Sparks on site) | NVIDIA-hosted; build agents on **Nemotron**/NemoClaw | **ClawForge** (cloud: no-code small-business agents, "NemoClaw safety-powered"); **FactoryMind** (edge: factory robot optimization); **MonkeyClaw** (NemoClaw track: cybersecurity tool that probes, patches and protects the NemoClaw ecosystem); **HydroClaw** (autonomous hydroponics farm manager). | [V: https://news.ucsc.edu/2026/06/agentic-ai-first-uc-santa-cruz-hackathon-with-nvidia-asus/]. Per-project model details [UNVERIFIED] (Devpost 403). |
| **NVIDIA Hack for Impact London** (Jun 5–7) | NVIDIA-hosted; "Best use and implementation of the NVIDIA Nemotron model" | **Codeborough** (Loughborough): "Agentic Facilities Assistant Navigator" for public services, built and run on a DGX Spark; DSIT offered commercialization support | [V: https://www.lboro.ac.uk/schools/science/news/2026/computer-science-researchers-win-national-ai-award/] |
| **NeMo Agent Toolkit Hackathon** (NVIDIA blog, Jul 17, 2025) | NVIDIA-hosted, 2 weeks | 1st: **Route Optimization Agent** (TCS Smart Mobility): constraint-extraction + routing agents call **cuOpt**, validate in **Omniverse**, deploy to **Jetson** robots. 2nd OpenCodeReview, 3rd Travel Planner (local fallback DB when APIs fail), HM macOS IoC cyber agent. Judged on "real-world applicability, technical execution, and how effectively they demonstrated agentic AI in action". | [V: https://developer.nvidia.com/blog/hackathon-winners-bring-agentic-ai-to-life-with-the-nvidia-nemo-agent-toolkit/]. NeMo Agent Toolkit is now deprecated (EOL end 2026) per prior research, so don't cite it as the stack. |
| **Nebius × NVIDIA Global AI Hackathon** (submissions closed Oct 30, 2026; $50k) | Needs Nebius + ≥1 NVIDIA open model (Nemotron, GR00T, Cosmos, Sonic) | **Winners not announced; scheduled Jan 25, 2027** [SS]. Judging = Technological Implementation, Design, Potential Impact, Quality of Idea (1–5 each) [V: Devpost updates]. | [V] rules summary on updates page. |
| **lablab.ai** events | Nemotron appears as a component, e.g. Heed (voice to-do agent, Nemotron 3.5 Lightning via Nebius), HireMate [SS: lablab.ai pages]. | No Nemotron-specific lablab winners verified. | Low value; deck cites lablab only generically ("Multi-Agent Research System"). |
| **Kaggle NVIDIA Nemotron Model Reasoning Challenge** | Not a hackathon (ended Jun 15, 2026; 1st $25k + 5 DGX Spark) [SS] | n/a | Skip. |

---

## 2. What NVIDIA DevRel judges reward

### 2a. Primary statements and rubrics

| Source | Statement | Status |
|---|---|---|
| HackUTD 2026 deck (Einhorn), slide 2 | Must go "Beyond a Chatbot: not just responding directly to prompts"; **multi-step workflows** ("agents that plan and execute complex tasks"); **tool integration** ("external APIs and services intelligently"); **real-world applicability** ("solving actual problems") | [V] `sources/nvidia-hackutd26.pdf` |
| Same deck, slide 10 "What wins" | Multi-agent systems (e.g. Research→Outline→Writer→Editor); agentic RAG ("decide WHEN to retrieve"); ReAct (Reason→Act→Observe); tool-calling apps; multi-modal agents (reasoning + VLM); **agent simulation & eval** ("generate realistic test scenarios and evaluation pipelines") | [V] |
| Same deck, slides 11–13 | Nemotron pitch = "the most open approach to AI development" (Catanzaro): models + datasets + techniques + tooling. Strengths: reasoning, function calling, autonomous decisions, RAG, multi-agent orchestration | [V] |
| Same deck, slide 14 | Past-winner examples cited: NeMo hackathon route-optimization agent, Dust hackathon bug-fixer, lablab.ai multi-agent research | [V]. Old reference set, so "multi-agent + tools" is the baseline judges expect, not a differentiator. |
| Ethan Einhorn (Sr. Product Marketing Manager) via Retrograde, Dec 2025 | Focus on communication and explaining complex ideas simply | [V] https://retrogradenews.com/2025/12/08/hackutd-marks-ten-years-of-hackathons-with-fantasy-and-fire-alarms/ |
| Shashank Verma (NVIDIA data scientist), same article | "Specialize in a company's tech stack before you compete"; students solve problems in unusual ways | [V] |
| Chris Alexiuk (NVIDIA deep learning dev), same article | Remembers apps "born from personal need" (a mechanic's shop app, a storybook generator); "make it clear you are passionate" | [V] |
| Nebius×NVIDIA judges (6 judges from Nebius, Tavily, NVIDIA) | "Solve a real problem for a real audience", "Get to the aha moment fast": two minutes into the project, 30 seconds into the demo | [V] index of https://nebiusglobalaihackathon.devpost.com/updates (item page 403) |
| Nebius×NVIDIA track guidance | "A single API call demo works; a **multi-step autonomous workflow that chains tools end to end** stands out." Physical AI: "a scripted demo is table stakes; **hardware reacting live to real-world input** is where this track can really shine." | [V] https://nebiusglobalaihackathon.devpost.com/updates/46204-here-s-how-judging-works |
| Nota AI winners (Seoul) | Judge comment: quantitative plus qualitative evaluation was the differentiator; the team also told judges the work "could plug straight into" an NVIDIA tool (NeMo Data Designer) and used "heavily the NVIDIA software stack"; earned points for knowing Nemotron | [V] https://blog.nota.ai/insights/nemotron-hackathon-winner |
| NeMo Agent Toolkit hackathon | "Real-world applicability, technical execution, how effectively they demonstrated agentic AI in action" | [V] NVIDIA blog |

### 2b. Secondary signals (search synthesis, treat with care)

A search summary of SteelHacks material says the track brief asked "where does Nemotron sit in the pipeline and why Nemotron", and favored Nemotron as **router / classifier / LLM-as-judge / planner** with **evals, benchmark comparison, or documented failures** [SS: steelhacks.org/tracks; page is a JS shell for me, nothing readable]. **[INFERENCE, supported]** by the structure of the two SteelHacks NVIDIA-track repos: both have a "Why Nemotron is essential/load-bearing" section and both report eval tables with honest failures (Bouncer, Verifier).

### 2c. Do judges value local / edge / open weights?

| Evidence | Reading |
|---|---|
| Prize hardware: Jetson Orin Nano Super (SteelHacks, TreeHacks, Nebius), DGX Spark (TreeHacks 1st/2nd, Seoul, UCSC), RTX 5080 (HackUTD), Brev credits everywhere [V] | NVIDIA is steering teams toward its hardware; a local demo shows them the hardware doing its job |
| TreeHacks has a dedicated **Edge AI Track**; TORQ won it with a Jetson Thor [V] | Edge is a first-class category at a top hackathon |
| UCSC Hack-a-Claw and HackMIT: DGX Spark / GX10 on site; ASUS says local agentic AI "is the correct architecture of choice" for sensitive data [V ASUS page] | The 2026 NVIDIA/ASUS narrative is *on-prem, private, agentic*. (This is vendor marketing.) |
| Detour: "for time-sensitive operations, latency is a safety risk"; ran air-gapped on Spark [V] | Edge justified by *safety*, which fits Interlock's story |
| Open Agent Safety Platform blog, principle 4: "An advantage of open models is that the entire reasoning space and activations are all visible" [V] | Open weights as a *safety property* is NVIDIA's own message |
| Counter-evidence: Toyotron (1st, 2025) used Nemotron via OpenRouter, not local [V]. HackUTD deck lists **build.nvidia.com, OpenRouter, or Hugging Face weights** in that order, and gives $60 Brev [V] | Hosted API is fully accepted at HackUTD. Local is a bonus, not a requirement. |
| TORQ (1st in Edge) used no Nemotron model; Alpamayo plus a cloud H100 [V repo] | Edge-track judges rewarded the NVIDIA *hardware and stack*, not specifically Nemotron |

**Conclusion [INFERENCE]:** Run Nemotron through the hosted API for the demo, and have a **one-command local mode** (Lightning NVFP4 or Nano on a Brev GPU, or Bolt E4B on the Jetson if one is available) to show. Pitch line: "same open weights, can run on-prem next to the plant, reasoning visible, but the safety does not depend on trusting it."

### 2d. Brev / hardware facts relevant to a local mode

| Item | Fact | Status |
|---|---|---|
| Brev credits | $60 per Nemotron-track team at HackUTD [V deck]; also $200 in the prizes | [V] |
| Ultra 550B | Not self-hostable on that budget; needs ≥4×B200 or 8×H100 (prior research from model card) | prior research |
| Lightning 30B-A3B NVFP4 | Supported on Blackwell, Hopper (NVFP4/W4A16), Ampere (W4A16) [V model card]. A single rented GPU is plausible [INFERENCE] | [V]/[INFERENCE] |
| Nano Omni 30B-A3B NVFP4 | Listed for DGX Spark, Jetson Thor, RTX 5090, RTX Pro 6000, H100/B200; vLLM 0.20.0; `--reasoning-parser nemotron_v3 --enable-auto-tool-choice` [V model card] | [V] |
| Jetson Orin Nano Super (8 GB) | Runs 4B-class models (Nemotron-3 Nano 4B, Bolt E4B) at ~20–30 tok/s per community posts | [SS/UNVERIFIED], third-party only |

---

## 3. Nemotron lineup relevant to a demo (late 2026)

Catalog fetched from https://build.nvidia.com/models.md (109 models; page 1 read) [V].

### 3a. Language models

| Model (build.nvidia.com id) | Size / notes | Reasoning toggle | Tool calling | Demo fit |
|---|---|---|---|---|
| `nemotron-3-ultra-550b-a55b` | 550B / 55B active hybrid Mamba-Transformer MoE, 1M ctx, released 2026-06-04 [V catalog, prior research] | `enable_thinking` on/off | Yes | Strongest; slow; hosted only. Used by Loomin (GTC), as "corrupter" in Verifier |
| `nemotron-3-super-120b-a12b` (+ `3.5-super-vl-120b-a12b` early access, multimodal) | 120B / 12B active | thinking on/off (Verifier used `thinking=False` for routing, `True` for audit [V]) | Yes | The workhorse in the SteelHacks NVIDIA projects (Bouncer, Verifier, Heard) |
| `nemotron-3.5-lightning-30b-a3b` | 30B / 3B active, hybrid Mamba-2 + MoE + attention, 1M ctx, NVFP4 checkpoint, MTP speculative decoding, "1.0-preview", 2026-08-11. Benchmarks (NVFP4): SWE-bench Verified 52.8, Terminal-Bench 2.1 23.5, **τ³-bench Banking 9.5**, IFBench 72.9 [V card] | Not described on the card | Trained with multi-step tool-use RL | Fast sub-agent. **Reliability caveat:** Bouncer saw timeouts/truncated JSON on the hosted API [V]; Weave tamed 10–30 s tails by turning reasoning off, hedging at 3 s, and falling back across providers [V] |
| `nemotron-3.5-bolt-e4b` | 8B total / 4B effective, post-trained from Gemma-4-E4B, GA 2026-10-23. BFCL v3 71.3, ToolSandbox 61.1, Tau2 63.2, IFEval-style IHEval 86.0 [V card] | Optional reasoning trace; `conversational_mode` flag | Yes; **async tool-calling** pattern documented on the card | The edge-sized option (Jetson Orin Nano Super class). Card says it is primarily for customization, not direct production use. Endpoint context 64K |
| Nemotron-3-Nano-30B-A3B (NVFP4) | Used on DGX Spark via vLLM in Detour [V] | thinking budget | Yes | Local-on-Spark proven at TreeHacks |
| `nemotron-3-nano-omni-30b-a3b-reasoning` | 31B / 3B active, **video (≤2 min), audio, image, text**, 256K ctx, 2026-04-28 [V card] | Thinking mode (temp 0.6, reasoning_budget 16384) vs Instruct mode (temp 0.2) [V] | Yes; JSON output | **The VLM/multimodal option.** Supported on DGX Spark, Jetson Thor, RTX 5090. Fits a camera-on-the-tank-rig idea [INFERENCE] |
| Nemotron Nano 12B v2 VL | Vision-language; documented for Jetson Thor (NVFP4-QAD) | n/a | n/a | [SS: jetson-ai-lab.com]; older than Omni |

### 3b. Safety and guardrail stack (NVIDIA's own)

| Component | What it does | Fit for Interlock | Status |
|---|---|---|---|
| **Nemotron 3.5 Content Safety** (`nemotron-3.5-content-safety`, 4B on Gemma-3-4B, LoRA; build.nvidia.com 2026-06-02, HF 2026-03-16/06-04) | Prompt + optional image + optional response → safe/unsafe + categories (Aegis taxonomy, 23 categories); **custom natural-language policy**; optional `<think>` auditable reasoning; ~140 languages by transfer; 8 GB+ VRAM; vLLM | **Layer 0:** screen judge phone prompts. Custom policy can encode "no instruction to bypass limits". Think-mode trace is a good on-screen audit line. | [V] model card + HF blog |
| **Llama-3.1-Nemotron-Safety-Guard-8B-v3** | Multilingual (9 langs) prompt/response safety, 23 categories, 8K ctx; card admits it "remains susceptible to adversarial prompts" | Alternative layer 0; older | [V] |
| **NemoGuard JailbreakDetect** | Random Forest on 768-d embeddings; F1 0.96 on JailbreakHub; FPR 0.4%, FNR 4.4% | Cheap layer 0 for the "judges attack from phones" flow | [V] |
| NemoGuard 8B content-safety and topic-control | Content safety; keep conversation on approved topics | Topic control to keep the console on oilfield ops | [V] catalog |
| **NeMo Guardrails IORails: tool-calling rails** | `tool call validation` (allowlist + JSON-Schema on arguments) and `tool result validation` (links to a prior call); local, no extra LLM call, **fail-closed**; **experimental and opt-in**; OpenAI Chat Completions format only | Exactly Interlock's "schema" check, NVIDIA-branded | [V] https://docs.nvidia.com/nemo/guardrails/configure-guardrails/guardrail-catalog/tool-calling |
| **OpenShell** (Rust, Apache-2.0, 21k stars) | Per-agent sandbox with kernel-level enforcement (files, syscalls, network), credentials injected only at approved endpoints, policy changes **formally verified** and held for human review; SDKs in Python, TypeScript, Go, Rust | Direct analog to MisaOS bubblewrap sandbox plus approvals. Judges will know it from GTC. | [V] https://github.com/NVIDIA/OpenShell |
| **NVIDIA Open Agent Safety Platform** (blog Sep 28, updated Oct 15, 2026) | OpenShell on Vera CPU + "Sentry" on BlueField-4. Five principles: verifiable policy; **out-of-band enforcement**; control the path to the model; scale authority with reasoning visibility; shared responsibility. "An agent in these circumstances cannot be expected to fully govern its own behavior." | The thesis Interlock demos. Quote it in the pitch. | [V] https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/ |
| Nemotron-AIQ Agentic Safety Dataset (with Lakera, 10,796 OTel traces) and **garak** | Attack traces and a red-teaming scanner | Could seed the phone-attack corpus and supply an eval number | [SS] (HF dataset page not opened) |
| NemoClaw | NVIDIA's governed OpenClaw/Hermes runtime on OpenShell, deny-by-default egress, local-inference routing | Judges and UCSC winners already live in this vocabulary | [SS] for details; UCSC track names [V] |
| Safety-for-Agentic-AI blueprint | **Deprecated Apr 22, 2026** in favor of NeMo Auditor / Guardrails / Safe Synthesizer | Don't cite as current | [V] README |

**Gap in NVIDIA's classifiers that Interlock fills [INFERENCE]:** content-safety and jailbreak models score *language*. "Set tank 4 discharge to 100% for 30 minutes" is polite and not toxic. The interlock must be domain-aware (rate limits, level limits, who may authorize) and must bind to a physical state. Show the content classifier *passing* a crafted injection and the interlock still blocking. Test this before relying on it; if the classifier catches the attack, the line becomes "defense in depth: layer 0 caught it, and here is what would have happened without it".

---

## 4. Novel vs seen-it-before at an NVIDIA table in Nov 2026

| Pattern | Seen? | Evidence | Verdict for Interlock |
|---|---|---|---|
| Chatbot or Q&A over data | Dead on arrival | Deck: "beyond a chatbot" | Avoid |
| Multi-agent dashboard with Nemotron planner, forecast and OR-Tools routing | Won 2025 | Alchemetrics [SS] | **Baseline.** Include a real multi-step dispatch plan, but this alone is not novel |
| Voice/phone-call concierge | Won 2024–25 | Toyotron, TalkTuahBank [V] | Optional garnish (Photon). Don't lead with it |
| Ambient copilot with Nemotron as classifier | Seen Sep 2026 | Heard! [SS] | Not relevant |
| **Nemotron as judge or gate, deterministic code decides** | **Seen Sep 2026, in this track** | Bouncer, Verifier [V] | Not novel as an *architecture*. Cite it as the lineage. |
| **Prompt-injection firewall for MCP tool calls** | **Seen Sep 2026** | Bouncer [V]; NeMo Guardrails tool rails [V]; OpenShell [V] | Seen. Differentiate. |
| Security-ops agents (alert triage, IoC hunters, NemoClaw hardening) | Seen | Casefile [SS], 2025 macOS cyber agent [V], MonkeyClaw [V] | Seen |
| Edge/physical autonomy on Jetson (car, gantry, hydroponics, factory robots) | Seen at TreeHacks and UCSC, rewarded | TORQ, Sprout, HydroClaw, FactoryMind [V] | A physical rig is a **plus**, but expect a few of these. Tie the physics to the safety claim so it isn't decoration |
| Local on DGX Spark, air-gapped, "latency is safety" | Seen | Detour [V] | Optional toggle |
| Planner/Safety agent pair with deterministic physics | Seen once | Detour [V] | Closest conceptual neighbor on the *physical* side. Its "safety agent" is still an LLM. |
| Eval table with honest failures, ablation switch | Seen in the better SteelHacks entries and rewarded in Seoul | Verifier "None" dropdown; Nota [V] | **Required**, not novel |
| **Ed25519-signed human approvals + verifiable receipts, checked outside the model** | **Not found** [INFERENCE from my sample] | OpenShell has policy approval but not signed receipts in what I read; none of the entries do | **Genuinely differentiated.** Make "who authorized this, provably" visible: a receipt the judge can verify on their phone |
| **Physical-limit interlock with the LLM having no authority** (SIS-style) | Not found as a demo [INFERENCE] | Detour approximates | **Differentiated** if the rig refuses in hardware (relay stays open). A 5-second visual |
| **Live audience red-team from phones, scoreboard of blocked attacks** | Not found. Bouncer's demo was a 29 s scripted replay [V] | n/a | **Differentiated and fits 2-minute judging.** Risk: judges get stuck, run out of time, or find an actual bypass |
| Using NVIDIA's own safety models as measured layers (content safety → tool-call rail → physics → signature) | Partially (NemoClaw "safety-powered") | ClawForge [V title only] | A per-layer "stopped N of M attacks" waterfall would be new and is exactly the "agent simulation & eval" item on the deck |

### Positioning recommendation [INFERENCE]

1. **Lead with the agent doing real work** (multi-step EOG dispatch with a cuOpt or exact planner, showing dollars), then the attack, so judges see "agent beyond a chatbot" before "safety". Judges score the track brief first (multi-step, tools, real-world).
2. **Name the lineage and the delta in one sentence:** "Bouncer-style intent checks and NeMo Guardrails validate *what the model asked for*; Interlock also validates it against *plant physics* and *cryptographic authority* that the model can't forge." Do not claim to be first at injection blocking.
3. **Bring numbers:** N attacks (phone-sourced plus a scripted corpus, optionally garak or AgentDojo-style), blocked per layer, false-block rate on benign operator actions, p50 latency. Add an ablation toggle (interlock OFF / content-safety only / full).
4. **Keep the LLM non-authoritative on stage.** Teams in this track found Nemotron miscalibrated on exactly the decisions you'd gate (Verifier: 4× aspirin overdose rated "medium"; Bouncer: 31 of 36 AgentDojo catches were ASK, i.e. over-cautious). Their lesson matches your design; cite it.
5. **Reliability plan:** reasoning off for the hot path; hedge at ~3 s; fail closed and say so on screen; secondary model or local fallback; pre-warm; rate-limit judge phones. Hosted free tiers may throttle a crowd.
6. **Rename or disambiguate "Interlock"** (SteelHacks had a different project of that name).
7. **Use the hardware you have** (ESP32-S3 + relay + water-level sensors): a miniature tank and valve whose actuation is gated by the signed-approval receipt. Keep the claim honest: it is a model of the plant, not the plant.

## Gaps and unverified items

- SteelHacks XIII NVIDIA winners (3 teams): the gallery shows no badges in fetched text; Devpost project pages for Heard! returned 403. Ask on the HackUTD NVIDIA booth or open the gallery filtered by prize in a normal browser.
- Alchemetrics, FactoryMind, HydroClaw Devpost pages: 403; details are search-summary level.
- HackMIT 2026, Cal Hacks 13, MHacks 2026: only search summaries; absence of a Nemotron track not proven.
- Whether NVIDIA staff at HackUTD 2026 were involved in SteelHacks judging: not proven (the deck footer references SteelHacks XIII; the judge list on the SteelHacks Devpost page did not show NVIDIA names in the part I read).
- Einhorn's view on local vs hosted: no direct statement found.
- Nemotron Nano 12B VL Jetson claim and Orin Nano tokens/sec figure: third-party only.
