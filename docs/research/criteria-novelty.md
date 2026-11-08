# Novelty and saturation map for 8 idea families

Collected Sat 2026-11-07 for HackUTD 2026 (Nov 7-8). Scope: criterion 1 (novelty) only. Main copies this to `Tracks/research/criteria-novelty.md`.

## Key findings

1. **The software-only Interlock is the most saturated cell I found.** At least 19 Devpost projects surfaced with the same shape (agent proposes, deterministic gate disposes, injection demo, Ed25519/hash-chain log). I opened 5; all started Aug 15 - Nov 4, 2026. Four more sit in one hackathon (PayPal AI Hackathon, closes Nov 12).
2. **NVIDIA judges own the prior art:** NeMo Guardrails (7,449 stars), garak, Nemotron Safety Guard, OpenShell (21,251 stars, created 2026-02-24), NemoClaw, Agent Policy Fabric (Cedar, signed policy bundles). Expect "isn't this OpenShell + APF + NeMo Guardrails?" first.
3. **Signed, hash-chained receipts are table stakes** (at least 10 Devpost projects, 160 GitHub repos matching "signed receipts" + agent, plus AP2 / Visa TAP / Cloudflare signed agents as standards). The team's MisaOS strengths (Ed25519 approvals, receipts, bwrap) map onto the MOST saturated features.
4. **"Try to jailbreak it" is an established genre** (Gandalf 2023, Agent Breaker Sep 2025, Gray Swan Arena 1.8M attacks, DEF CON booths). Good hook, weak as the idea itself.
5. **Thinnest cell: LLM agent + physical process + hardware-level last defense, attacked live.** No hackathon project of that shape surfaced in about 40 searches and fetches [UNVERIFIED absence]. Nearest are papers (PLCBench, RIPA) and repos (esp32-mcp). None has a win.
6. **Physical demos win at robotics events** (LeRobot hackathon: 3,000+ people, 44 countries) **but are rare at software hackathons.** A Cal Hacks 12 grand-prize winner calls robotics "not really feasible" in a weekend. Novelty is paid for in rig-reliability risk.
7. **Voice:** HackUTD judges saw TalkTuahBank ('24) and Toyotron ('25). Cal Hacks 12's grand prize (FaceTimeOS) and TAMUhack '25 (TalkTuahAirline) were voice agents too. A phone call from an AI is expected now.
8. **COBOL** is saturated by incumbents (AWS Transform, IBM, Anthropic's Feb 23, 2026 playbook; IBM fell 13%) and has at least 8 Devpost projects, including an execution-verified one that placed 3rd (Synco). Only worth it for the 8090 track.
9. **Twins/cascades:** at least 8 Devpost projects; NVIDIA DSX + Cadence + Siemens own the polished version. LLM red-vs-blue is research-saturated and hackathon-thin.
10. **Net [INFERENCE]:** novelty must come from the combination: physical rig, independent hardware layer, live human + automated attackers, per-layer catch counter, receipts binding approval -> setpoint -> sensor outcome. Grades: [V] I opened it, [S] search-tool summary only, [U] unverified, [I] inference.

## Method and limits

- Devpost project pages and all Devpost search / "built-with" pages mostly return HTTP 403. **No Devpost totals exist here.** "Count" means distinct projects surfaced by at most 3 searches per family (a lower bound).
- GitHub totals come from the GitHub search API on 2026-11-07. README-phrase queries undercount; topic queries overcount.
- **Correction:** the first-pass search called Spiderbusters (Technica '25) and "CrackTheCode" (HopHacks '25) winners. A second pass found no winner badge for Spiderbusters, and "Crack the Code" at prompt-injection-game.onrender.com is a separate game. Treat both as NOT winners.
- Cal Hacks 13 (Oct 23-25, 2026) grand prize and the PayPal AI Hackathon winners (due Dec 21, 2026) are not available yet.
- Not checked: HackAPrompt, Meta LlamaFirewall, Microsoft Prompt Shields, Cisco AI Defense, Product Hunt for families 3-8.

## Summary table

Saturation: Low / Med / High. "Hack" = 2025-26 hackathons, "Prod" = startups and products.

| # | Family | Hack | Prod | Lower-bound counts | Likely "isn't this just...?" | Angle that still reads new (Nov 2026) [I] |
|---|---|---|---|---|---|---|
| 1 | Prompt-injection / red-team games | Med-High | High | Devpost >=6; GH `"prompt injection" ctf` 115, `topic:prompt-injection` 6,500; PH >=1 | Gandalf / Agent Breaker; Gray Swan Arena | Win condition is a physical consequence scored by sensors; injection through operational data fields; live "reached the actuator = 0" counter |
| 2 | Guardrails / policy engines / interlocks | High | High | Devpost >=10; GH `topic:llm-guardrails` 327, `topic:mcp-security` 636, "agent firewall" 218; PH >=10 | NeMo Guardrails, OpenShell + APF, Lakera, Invariant | Process-physics invariants; independent hardware layer; block -> cheapest safe alternative; per-layer catch counts |
| 3 | AI agents for OT / SCADA | Med | High (incumbents) | Devpost >=7; GH `modbus mcp` 77 | Honeywell Experion Operations Assistant, Siemens industrial AI agents, Cognite Atlas AI | Agent that actually actuates a rig under bounded authority (most hackathon entries deny writes) |
| 4 | Signed agent logs / receipts | High (2026) | Med-High, rising | Devpost >=10; GH "signed receipts" agent 160 | AP2 mandates, Visa TAP, Cloudflare signed agents, NVIDIA APF audit | Receipt binds approval -> setpoint -> sensor before/after; judge verifies offline from a QR |
| 5 | COBOL / legacy modernization | Med-High | High | Devpost >=8; GH 27-30 | AWS Transform, IBM watsonx Code Assistant for Z, Claude Code playbook | Per-rule equivalence certificate against real GnuCOBOL (incremental over Synco) |
| 6 | Twins with cascades; attacker-vs-defender wargames | Twins Med-High; wargames Med | Twins High; wargame research High | Devpost >=8 twins, >=4 wargame/pentest | NVIDIA Omniverse DSX + Cadence; CybORG / CyberBattleSim / AIxCC | Twin-vs-reality residual on a tiny physical plant; automated attacker vs interlock with live scoreboard |
| 7 | Voice / phone agents | High | High | Devpost >=8 winners or mentions | TalkTuahBank, Toyotron (both HackUTD winners) | Voice as attack surface (vishing the agent) or approval channel, not as convenience |
| 8 | Physical-world agents | Low-Med at software hacks; High at robotics hacks | Med-High | Devpost >=8; GH `topic:ros2 llm` 155, "px4 llm drone" 21 | ROSA, LeRobot/VLA demos, drone-copilot | Process-control rig (tanks, valves) driven by discrete LLM commands; embodied injection (sign or QR in camera view) |

## Cross-cutting: the Aug-Nov 2026 cluster next to Interlock

| Project | Started | Gate | Receipts | Injection demo | Physical? | Grade / URL |
|---|---|---|---|---|---|---|
| Agent Firewall | Aug 15, 2026 | MCP proxy, intent-drift check (Claude); fail-safe block | audit log | Yes; 504 calls, recall 0.87, FPR 0.12 vs 0.50 signature baseline | No | [V] https://devpost.com/software/agent-firewall-i392mt |
| Epyk Forge | Aug 31, 2026 | Deterministic Supervisor; "PLC writes, servo resets denied" | decision trace | Yes (injected KB docs, Security Center) | No (synthetic factory) | [V] https://devpost.com/software/epyk-forge |
| Verso | Aug 31, 2026 | PDF ingestion firewall (Foxit / Nutrient tracks) | Ed25519, chained | Hidden-text PDFs | No | [V] https://devpost.com/software/verso-w72u95 |
| Agent Spend Gate | Oct 17, 2026 | Caps + page-evidence check; MCP server | Ed25519, hash-chained | Yes, 10/10 attacks denied | No | [V] https://devpost.com/software/agent-spend-gate |
| SentinelPay | Nov 4, 2026 | Caps / allowlists / freeze; "model proposes, code decides" | Ed25519 checkpoints + hash chain | Yes (gift-card injection) | No | [V] https://devpost.com/software/sentinelpay-g6l7m9 |
| VaultPay Guard, Agent Payment Firewall | Oct-Nov 2026 | 5-stage firewall; proxy | AG Grid audit log | Yes | No | [S] https://devpost.com/software/agent-payment-firewall-8pdbtw |
| Sentinel, AgentGuard x2, PromptGuard, GURADRAIL | n/a | tool-call firewall / PBAC | some | Yes | No | [S] https://devpost.com/software/sentinel-g7xw9q , https://devpost.com/software/agentguard-6qaw9k , https://devpost.com/software/agentguard-qjwk6s , https://devpost.com/software/guradrail |
| ControlPlane, Lex Aureon, Eudora, Gatehouse, Dhurandhar, Proofline | n/a | governance layers | signed / hash-chained | some | No | [S] https://devpost.com/software/controlplane , https://devpost.com/software/eudora , https://devpost.com/software/gatehouse-qh9ml4 |

The PayPal AI Hackathon ran Oct 1 - Nov 12, 2026, with winners announced Dec 21 ([S] https://paypalaihackathon.devpost.com/ , https://developer.paypal.com/community/blog/PayPal_AI_Hackathon/). None of these has been judged, so none is a proven winner. Agent Firewall and Epyk Forge host hackathons were not identified.

## 1. Prompt-injection / red-team games (live jailbreak, "hack the agent")

**Saturation:** Hack Med-High (educational games and red-team harnesses are a recurring genre); Prod High (Lakera sold for about $300M).

| Item | Evidence | URL | Grade |
|---|---|---|---|
| Gandalf / Agent Breaker (Lakera) | Gandalf May 2023; Agent Breaker Sep 2025 (10 simulated GenAI apps, indirect injection, tool abuse); Lakera claims 2M+ players, 80M+ attempts | https://gamesbeat.com/lakera-launches-hacking-sim-gandalf-agent-breaker/ , https://play.lakera.ai/ | S |
| Check Point buys Lakera | Sep 16, 2025, est. $300M | https://www.checkpoint.com/press-releases/check-point-acquires-lakera-to-deliver-end-to-end-ai-security-for-enterprises/ | S |
| Gray Swan x UK AISI Arena | Mar 8 - Apr 6, 2025; 1.8M attacks, 62K policy violations, $171.8K prizes, 22 models, 44 scenarios | https://arxiv.org/abs/2507.20526 | S |
| HackAIcon "Hack the Agent" (Ethiack) | 5-level ticketing-agent CTF; level 5 is indirect injection via a URL the agent browses | https://hackaicon.ethiack.com/ , https://cryptocat.me/blog/ctf/2025/hack-the-agent/ai/ | S |
| Pangea AI Escape Room | 2025; $10K pool; over 1,000 players, 86 finished | https://pangea.cloud/blog/ethical-hackers-mindset-leads-to-victory-in-pangea-ai-challenge/ | S |
| Microsoft LLMail-Inject | IEEE SaTML 2025 adaptive challenge against an email agent | https://www.microsoft.com/en-us/msrc/blog/2025/03/announcing-the-winners-of-the-adaptive-prompt-injection-challenge-llmail-inject | S |
| Promptfoo live booths | DEF CON 2026, SecTor 2025: attendees red-team vulnerable agents | https://www.promptfoo.dev/events/defcon-2026/ | S |
| Great Agent Hack 2025 (London, Nov 15-16) | $65K; Track C = security / red teaming. Official page: Introspect AI 1st, HSIA 2nd, BiasSphere 3rd. Grand Champion: Jailbreak Lab (red-team platform; 7 secret animal-named agents). Recap blog names HSIA as Track C winner (conflict) | https://hackathon.holisticai.com/ , https://www.holisticai.com/blog/what-we-learned-from-the-great-agent-hack-2025 | S |
| Spiderbusters (Technica '25) | Educational jailbreak-defense game; real submission; **no winner badge seen** | https://technica-2025.devpost.com/project-gallery | S (win U) |
| A Deal with the Devil; Spectra | Roguelite with an adversarial LLM; red-team arena | https://devpost.com/software/a-deal-with-the-devil , https://devpost.com/software/spectra-8rtuo1 | S |
| GitHub | `"prompt injection" ctf` 115 repos; `topic:prompt-injection` 6,500; LLMVault (352 stars, created 2026-07-15); Tensor Trust | https://github.com/CyberSunil/LLMVault , https://github.com/HumanCompatibleAI/tensor-trust | V |
| Product Hunt | Agent Arena | https://www.producthunt.com/products/agent-arena | S |

**Won vs existed:** only Jailbreak Lab (Great Agent Hack grand champion) is a winner I could source [S]. Everything else existed or is unconfirmed.

**Angles that read new [I]:**
- The attacker's goal is a physical consequence (spill, deadhead, dry-run) judged by sensors. Gandalf, Tensor Trust and HackAIcon all use secrets, flags or software tool abuse.
- Injection through operational data fields (work-order text, tag annotations, driver SMS from the EOG dataset). RIPA shows sensor-channel injection works on robots (below), so it is credible.
- Same attack run twice: unprotected rig (spill) vs protected rig. Publish a live counter: N attempts, M fooled the LLM, 0 reached the actuator.

**Closest prior art a judge names:** Gandalf; Gray Swan Arena; HackAIcon's "Hack the Agent". **Risk:** phone typing in a 2-minute slot is slow; use a QR code -> web attack console with preset payload buttons plus free text [I].

## 2. Guardrails, policy engines, safety interlocks for tool-calling agents

**Saturation:** Hack High; Prod High. Six vendors in this space were bought in 2025, and NVIDIA ships its own stack.

| Item | Evidence | URL | Grade |
|---|---|---|---|
| NeMo Guardrails | 7,449 stars, 898 forks, created 2023-04-18 | https://github.com/NVIDIA-NeMo/Guardrails | V |
| NVIDIA OpenShell | 21,251 stars, created 2026-02-24, Rust, "safe, private runtime for autonomous AI agents" | https://github.com/NVIDIA/OpenShell | V |
| Safety for Agentic AI blueprint, Agent Policy Fabric, NemoClaw | garak red-teaming + NeMo Guardrails / Nemotron Safety Guard + OpenShell sandbox + APF (Cedar policies, signed bundles, tamper-evident audit events) | https://github.com/NVIDIA-AI-Blueprints/safety-for-agentic-ai , https://docs.nvidia.com/agent-policy-fabric , https://github.com/NVIDIA/NemoClaw | S |
| 2025 M&A | Lakera -> Check Point (est. $300M); Invariant Labs -> Snyk (Jun 2025); Prompt Security -> SentinelOne (about $159-250M); CalypsoAI -> F5 ($180M); Pangea -> CrowdStrike (about $260M); Protect AI -> Palo Alto | https://snyk.io/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation/ , https://www.f5.com/company/news/press-releases/f5-to-acquire-calypsoai-to-bring-advanced-ai-guardrails-to-large-enterprises , https://www.crowdstrike.com/en-us/press-releases/crowdstrike-to-acquire-pangea-to-secure-every-layer-of-enterprise-ai/ , https://www.sentinelone.com/press/sentinelone-to-acquire-prompt-security-to-advance-genai-security/ , https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai | S |
| Research | CaMeL (DeepMind), AgentSpec (ICSE 2026), RoboGuard (physical-robot guardrails) | https://arxiv.org/abs/2503.18666 , https://robo-guard.github.io/ , https://simonw.substack.com/p/camel-offers-a-promising-new-direction | S |
| Product Hunt 2026 | Permit MCP Gateway (Mar 18), Aegisora (Aug 5/21), Arcjet (Sep 21 / Oct 9), mcpgawk (Oct 12), HOL Guard, Golf, Execlave, Constellation Gate AI (Jun), Agent Browser Shield, keychains.dev | https://www.producthunt.com/products/arcjet , https://www.producthunt.com/products/aegisora , https://www.producthunt.com/products/permit-io , https://www.producthunt.com/products/hol-guard , https://www.producthunt.com/products/mcpgawk | S |
| Devpost | Agent Firewall [V]; Sentinel, AgentGuard x2, PromptGuard (HackEurope gallery p5), GURADRAIL [S] | see cluster table | V/S |
| GitHub | `topic:llm-guardrails` 327; `topic:mcp-security` 636; "agent firewall" 218 | api.github.com search, 2026-11-07 | V |

**Won vs existed:** I found no verified winner. Agent Firewall publishes honest numbers (recall 0.87, FPR 0.12, 63 "legit wording, excessive action" cases: signature scanner 0, firewall 35), which sets the bar for how a gate is evaluated [V].

**Angles that read new [I]:**
- Limits derived from process state (tank level + inflow - outflow, pump curve, truck ETA / capacity), not caps or allowlists. The 2026 cluster is almost entirely finance/caps/allowlists.
- Map layers to IEC 61511 / layer-of-protection thinking: LLM never in the safety loop; independent layer below it. A Kenexis article states IEC 61511 excludes non-deterministic ML from safety functions [S: https://www.kenexis.com/artificial-intelligence-in-safety-systems-is-coming/].
- Block -> **repair**: when the gate refuses, return the cheapest safe alternative using the EOG cost model, so the gate plans instead of only refusing.
- Per-layer catch counter (LLM refusal / guard model / schema / limits / approval / hardware cutoff), the Swiss-cheese view.
- Avoid leaning on "LLM judges LLM"; Agent Firewall already faced the "Claude vs Claude" objection.

**Closest prior art a judge names:** NeMo Guardrails; OpenShell + APF (NVIDIA); Lakera Guard; Invariant. **Honest answer:** those constrain what an agent may call; none checks process physics or has a hardware layer [I, not verified against their docs in depth].

## 3. AI agents for industrial control / SCADA / OT

**Saturation:** Hack Med (mostly "copilot + dashboard + actuation denied"); Prod High at incumbents.

| Item | Evidence | URL | Grade |
|---|---|---|---|
| Siemens | Industrial Copilot grew into industrial AI agents + Digital Twin Composer (with NVIDIA Omniverse) | https://press.siemens.com/global/en/pressrelease/siemens-introduces-ai-agents-industrial-automation , https://blog.siemens.com/2026/03/the-future-of-industrial-ai-is-agentic/ | S |
| Honeywell | Experion Operations Assistant (Chevron / TotalEnergies pilots, predicts alarm floods 5-12 min early); Experion Cognition | https://www.cxodigitalpulse.com/honeywell-unveils-commercial-launch-of-ai-powered-control-room-assistant-following-successful-pilot/ , https://erp.today/honeywell-experion-cognition-industrial-ai-ot-cybersecurity/ | S |
| Cognite Atlas AI; Rockwell FactoryTalk Conductor; ABB Genix Copilot; AVEVA; Schneider | Agent workbenches and copilots for plants | https://www.cognite.com/en/product/atlas , https://www.rockwellautomation.com/en-us/company/news/press-releases/Rockwell-Automation-Introduces-FactoryTalk-Conductor-an-AI-Native-Orchestration-Platform-for-Industrial-Automation.html , https://new.abb.com/news/detail/127990/abb-named-as-one-of-the-top-10-gen-ai-powered-industrial-copilot-vendors | S |
| Epyk Forge | 6 ADK agents on a synthetic factory; PLC writes denied; injected KB docs; "dashboards tell you what happened; Forge handles what happens next" | https://devpost.com/software/epyk-forge | V |
| SENTINEL-X, AURA-OPS (Nemotron 340B), K-Saver (allowlisted OPC UA setpoint after engineer approval), PlantMind (Nemotron, PLC tamper forensics), T-IA Copilot (Siemens SCL, GenAI Zurich) | Industrial agents on Devpost | https://devpost.com/software/sentinel-x-4ir8qu , https://devpost.com/software/aura-ops-webxr-industrial-digital-twin-ai-copilot , https://devpost.com/software/k-saver , https://devpost.com/software/plantmind , https://genaizurich.devpost.com/project-gallery?page=4 | S |
| Safety-gated LLM + PLC research | PLCBench (HIL, "can agents turn PLC access into physical impact"); step-level tool-call safety benchmark for ICS; "gatekeeper" framework paper | https://arxiv.org/html/2608.26882v1 , https://eurekamag.com/research/108/295/108295523.php , https://www.notatechguy.com/llm-agent-framework-blocks-hallucinated-actions-in-industrial-control/ | S |
| ESP32 / Modbus MCP repos | esp32-mcp (relays/GPIO for agents); ESP32-Modbus water-pump controller; GH `modbus mcp` 77 repos | https://github.com/StefanYasin/esp32-mcp , https://github.com/Diocta/ESP32-Modbus | S / V (count) |

**Won vs existed:** no OT-agent winner verified. HackUTD EOG 2024 winners (PipeBrAIns: Random Forest R^2 ~94%; DHy-n0: anomaly detection) used no LLM ([V] in past-winners.md). HackUTD 2025 had 2 EOG winners; names not retrievable. To an EOG judge, an agent + interlock is novel relative to those winners [I].

**Pattern:** hackathon OT agents mostly stop at advice. Epyk Forge denies PLC writes; K-Saver gates writes behind an engineer. An agent that **does** actuate a physical rig, with proof of what stopped it, is the unsettled gap [I].

**Closest prior art a judge names:** Honeywell Experion Operations Assistant; Siemens Industrial Copilot / agents; Cognite Atlas AI. **Honest answer:** those are advisory plant software; this is a bounded-authority actuation demo with an independent layer. Do not claim real-plant readiness (the "gatekeeper" paper itself cautions testbed results do not transfer to plants).

## 4. Signed, verifiable agent action logs / receipts / attestations

**Saturation:** Hack High in 2026; Prod Med-High and rising (standards from Google, Visa, Cloudflare, Ethereum).

| Item | Evidence | URL | Grade |
|---|---|---|---|
| SentinelPay, Agent Spend Gate, Verso | Ed25519-signed, hash-chained logs/receipts; tamper test | see cluster table | V |
| AP2 Autonomous Commerce, Dhurandhar ("agents that show receipts"), Proofline, Lex Aureon, ControlPlane (signed decision receipts), Eudora (RFC 3161 timestamps), Gatehouse | Receipt / hash-chain / attestation variants | https://devpost.com/software/p2-autonomous-commerce-cryptographic-agent-subscriptions , https://devpost.com/software/dhurandhar-ai-agents-that-show-receipts , https://devpost.com/software/next-gen-agent , https://devpost.com/software/lex-aureon-mathematical-constitution-governance-for-llm , https://devpost.com/software/controlplane | S |
| asqav-sdk | "Signed receipts, policy enforcement, audit trails"; 432 stars; created 2026-01-14 | https://github.com/jagmarques/asqav-sdk | V |
| GitHub | "signed receipts" agent: 160 repos | api.github.com, 2026-11-07 | V |
| Google AP2 | Signed Intent / Cart / Payment mandates; 60+ partners | https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol | S |
| Visa Trusted Agent Protocol; Mastercard Verifiable Intent | RFC 9421 HTTP message signatures for shopping agents | https://github.com/visa/trusted-agent-protocol , https://www.finextra.com/blogposting/31107/deep-dive-mastercard-verifiable-intent-vs-visa-trusted-agent-protocol | S |
| Cloudflare Signed Agents / Web Bot Auth | Ed25519 HTTP message signatures; IETF draft | https://blog.cloudflare.com/signed-agents , https://github.com/cloudflare/web-bot-auth | S |
| ERC-8004 "Trustless Agents" | On-chain identity / reputation / validation registries | https://eips.ethereum.org/EIPS/eip-8004 | S |
| NVIDIA APF | Signed policy bundles; tamper-evident `apf.audit.event.v1` | https://docs.nvidia.com/agent-policy-fabric | S |

**Won vs existed:** none verified as winners; the 2026 cluster is unjudged.

**Angles that read new [I]:**
- The receipt covers the physical outcome: signed human approval -> exact setpoint -> hash of sensor snapshot before and after -> relay state. I found no project that binds sensor state; this absence is unverified.
- "Verify it yourself": a judge scans a QR and verifies the chain in their browser against a printed public key.
- Frame it as an AP2-style **operation mandate** (scoped, time-boxed, setpoint-bounded) for physical actuation. Expect "isn't this AP2 mandates?" and answer: same primitive, different domain, with physical evidence.
- Recording denials and tamper tests is already done (Agent Spend Gate, Verso); do not present those as novel.

**Closest prior art a judge names:** AP2 mandates; C2PA / Sigstore-style provenance; Cloudflare signed agents; NVIDIA APF audit events.

## 5. COBOL / legacy modernization agents

**Saturation:** Hack Med-High; Prod High. Matters only for the 8090 track.

| Item | Evidence | URL | Grade |
|---|---|---|---|
| Anthropic playbook | Feb 23, 2026 post on Claude Code for COBOL; IBM fell about 13% that day | https://resources.anthropic.com/code-modernization-playbook , https://www.forbes.com/sites/tylerroush/2026/02/23/ibm-shares-plummet-13-worst-day-since-2000-after-anthropic-launches-programming-ai-tool/ | S |
| AWS Transform for mainframe; IBM watsonx Code Assistant for Z; Cognition (Devin) | Agentic COBOL -> Java/cloud pipelines | https://aws.amazon.com/transform/mainframe/ , https://www.ibm.com/docs/en/watsonx/watsonx-code-assistant-4z/2.x?topic=welcome-about-watsonx-code-assistant-z , https://cognition.com/blog/how-devin-is-modernizing-cobol-at-fortune-500-companies | S |
| Microsoft sample | "Legacy-Modernization-Agents": COBOL -> Java Quarkus with agents; 230 stars | https://github.com/Azure-Samples/Legacy-Modernization-Agents | V |
| Synco | Execution-verified COBOL -> Python with GnuCOBOL dual execution and self-heal; **3rd prize**, DigitalOcean Gradient AI Hackathon (2,630+ participants) | https://digitalocean.devpost.com/project-gallery , https://quochung.cyou/ | S |
| COBRA | AWS + Kiro + MCP, COBOL AST -> Lambda/CDK; started Nov 10, 2025; no winner badge in fetched text | https://devpost.com/software/cobra-cobol-banking-resilience-agent | V |
| COBOL Compass (GitLab AI Hackathon); Anathis (Bedrock / Nova, copybook -> EBCDIC); Logic Lift; COBOL Resurrection; COBOL Modernization Pipeline; LAME | More Devpost entries | https://devpost.com/software/cobol-compass-legacy-code-modernization-agent , https://devpost.com/software/anathis , https://devpost.com/software/cobol-resurrection , https://devpost.com/software/cobol-modernization-pipeline , https://devpost.com/software/lame-legacy-architecture-modernization-engine | S |
| GitHub | `topic:cobol llm` 27; "cobol modernization agent" 30 | api.github.com, 2026-11-07 | V |

**Won vs existed:** Synco 3rd place [S]; the others existed. No HackUTD or 8090 winner data exists (past-winners.md).

**Angle that reads new [I]:** execution-verified parity is already a placed idea. What remains is per-business-rule equivalence certificates with line citations (8090's own pitch), or "legacy" meaning PLC ladder logic / old SCADA scripts (ties to OT; T-IA Copilot only covers Siemens SCL generation). Still incremental.

**Closest prior art a judge names:** AWS Transform; IBM watsonx Code Assistant for Z; "Claude Code already does this" (the Feb 2026 episode makes that the default reply).

## 6. Data-center / building twins with cascades; attacker-vs-defender wargames

**Saturation:** Twins: Hack Med-High, Prod High. Wargames: Hack Med, research High.

| Item | Evidence | URL | Grade |
|---|---|---|---|
| NVIDIA Omniverse DSX Blueprint + Cadence Reality + Schneider ETAP | Failure injection (CDU trip, power-leg loss), cascade-aware AI-factory twin; Phaidra / Emerald AI train control agents in it | https://blogs.nvidia.com/blog/omniverse-dsx-blueprint/ , https://www.cadence.com/en_US/home/resources/technical-briefs/cadence-reality-digital-twin-platform-and-nvidia-omniverse-integration-tb.html | S |
| Siemens Digital Twin Composer | Twin-gated agent changes | https://press.siemens.com/jp/en/pressrelease/pr-20260106-1 | S |
| Devpost twins/cascades | NEXUS GRID (substation cascade, data-center / hospital weighting); Astra-Grid (3D data-center twin + edge robot); ORIGIN (service-dependency twin); Floorplan Intelligence and CoolShift (Nemotron via Nebius, MEP failure scenarios); APEX (Motter-Lai engine); IntelliSupply; SwanForge (adversarial cascade search) | https://devpost.com/software/nexus-grid-urban-energy-intelligence-platform , https://devpost.com/software/astra-grid , https://devpost.com/software/origin-myqak1 , https://devpost.com/software/floorplan-intelligence-brief-in-building-out , https://devpost.com/software/coolshift , https://devpost.com/software/apex-lyw9pz , https://devpost.com/software/intellisupply | S |
| HackUTD 2025 NVIDIA-track data-center agent | GridGuardian DC (Nemotron heat/power agent); not a winner | https://devpost.com/software/gridxguardian-dc | prior research |
| Wargames, research | CybORG CAGE-4, CyberBattleSim, DefenderBench, `llms-are-acd`, C-CyberBattleSim, CyberDojo (`--red llm --blue llm`) | https://github.com/cage-challenge/cage-challenge-4 , https://github.com/microsoft/DefenderBench , https://github.com/r4wd3r/llms-are-acd , https://github.com/satyamdas03/CyberDojo/blob/main/README.md | S |
| Wargames, events | DARPA AIxCC finals (Aug 2025: Team Atlanta 1st, Trail of Bits 2nd); SANS FIND EVIL! hackathon; NARA, autoPentest on Devpost | https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/ , https://findevil.devpost.com/ , https://devpost.com/software/nara-autonomous-red-teaming-agent , https://devpost.com/software/autopentest | S |

**Won vs existed:** no twin/cascade hackathon winner verified. AIxCC is a real, judged attacker-vs-defender event but not a student hackathon.

**Angles that read new [I]:**
- A cascade engine that outputs ranked interventions with dollar impact (what CBRE's brief asks for), not a visualization; avoid React Flow graph + Motter-Lai, which APEX / IntelliSupply already did.
- Twin of a tiny physical plant with a **twin-vs-reality residual** (predicted vs measured level), so the twin is checked against the world.
- Attacker-vs-defender with a live scoreboard: an automated Nemotron attacker loops against the interlock while judges join as human attackers.

**Closest prior art a judge names:** NVIDIA's DSX digital twin blueprint; CyberBattleSim / CybORG.

## 7. Voice / phone-call agents (Retell, Vapi)

**Saturation:** Hack High; Prod High.

| Item | Evidence | URL | Grade |
|---|---|---|---|
| TalkTuahBank | HackUTD 2024 overall + Goldman 1st; Retell | https://devpost.com/software/talktuahbank | V (prior research) |
| Toyotron | HackUTD 2025 NVIDIA + Toyota Financial Services 1st; Retell + Nemotron; 103 NVIDIA teams | https://devpost.com/software/toyotron | V (prior research) |
| FaceTimeOS | **Cal Hacks 12.0 1st overall** (695 projects, 3,000+ hackers); voice agent controls a Mac via FaceTime | https://blog.dylanlu.com/cal-hacks-12/ , https://github.com/ThePickleGawd/FaceTimeOS | V |
| TalkTuahAirline | TAMUhack 2025: 1st overall software + 3rd American Airlines challenge; Retell + Twilio + ElevenLabs; calls other passengers to swap seats | https://tamuhack-2025.devpost.com/ , https://devpost.com/software/talktuahairline | S |
| Orion | Wildfire dashboard with Vapi voice ops; Cal Hacks 12 submission (started Oct 26, 2025); **winner badge not seen** | https://devpost.com/software/orion-p5ayks | V page, win U |
| Tunnel (Hack the North 2025, Vapi prize), SentinelAI (HackDavis 2025, Retell), Raincheck (Agents in the Loop 2025, Vapi), Vocal AI | Claimed prize wins | https://devpost.com/software/tunnel-dqv1k4 , https://devpost.com/software/sentinelai-dec0jp , https://agents-in-the-loop-2025.devpost.com/project-gallery , https://devpost.com/software/vocai-ai-coach | S |
| Cal Hacks 13.0 | Oct 23-25, 2026, 1,918 participants; grand prize not yet retrievable | https://cal-hacks-13-0.devpost.com/ | V |
| GitHub | "vapi voice agent hackathon" 8 repos (narrow query, low signal) | api.github.com | V |

**Won vs existed:** winners verified or well sourced: TalkTuahBank, Toyotron, FaceTimeOS, TalkTuahAirline. A winner's own advice (FaceTimeOS author, Cal Hacks 12): judges mostly see the UI and demo, hardcode a fallback; he judged one hackathon where "almost every project was just a chatbot clone. Super boring" [V blog].

**Angles that read new [I]:** voice as the **attack channel** (a judge phones the agent and tries to social-engineer it into opening a valve; the gate still holds) or as the **approval channel** (agent phones the on-call operator; operator confirms with a signed code). Voice as convenience is not new.

**Closest prior art a judge names:** TalkTuahBank and Toyotron, both HackUTD winners that these judges (or their colleagues) have seen.

## 8. Physical-world agents (LLM driving drones, robots, hardware)

**Saturation:** Hack Low-Med at software hackathons, High at robotics hackathons; Prod Med-High.

### What won

| Winner | Event | Evidence | URL | Grade |
|---|---|---|---|---|
| Ez_2_AI (Team 250) | Hugging Face LeRobot Worldwide Hackathon, Jun 2025 | 1st in U.S., 2nd globally; 3,000+ participants, 44 countries; SO-100, pi0 / ACT / SmolVLA, shirt folding and pill sorting | https://lightning.ai/blog/lerobot-hackathon-winners | V |
| leChef | Same | Global 1st per summary; voice-ordered sandwich robot (SO-100/101 + linear rail) | https://robotics.growbotics.ai/es/projects/hardware/so-101-open-robot-arm/builds/lechef-sandwich-robot-hackathon-winner , https://huggingface.co/spaces/LeRobot-worldwide-hackathon/all-winners | S |
| Firebreathing Rubber Duckies; Matcha Bot (SIGRobotics) | Embodied AI hackathons, Mar and fall 2025 | Dual SO-100 pick-and-place; two SO-101 arms, GR00T N1.5, Jetson Thor | https://www.hackster.io/news/embodied-ai-hackathon-winners-announced-2dc69c76942e , https://www.hackster.io/sigrobotics/matcha-bot-sigrobotics-embodied-ai-hackathon-1st-place-f0e520 | S |
| drone-copilot | Gemini Live Agent Challenge; page started Mar 16, 2026 | Voice -> Gemini Live -> tool calls -> DJI Tello; "Winner, Best of Live Agents" per the search tool (the fetched text omitted the badge) | https://devpost.com/software/drone-copilot | V page, S badge |
| MedAssist; Vanguard_AI | Cyberwave "Robotic Agents" hackathons (SF Mar 2026, Milan Jun 2026) | Awardees: voice-directed dispensing arm; voice patrol / inspection robot | https://robotic-hackathon.devpost.com/ , https://devpost.com/software/medassist-ai-powered-medication-dispensing-agent | S |
| Cal Hacks 13.0 Best Use of Spacetime (7 winners) | Oct 2026 | Includes an ESP32 wristband that relights a concert (recap video description) | https://www.youtube.com/watch?v=geUtngSpwhs | S |
| Duet (EEG -> music) | Cal Hacks 11 overall, 2024 | Hardware-adjacent grand prize | https://stanforddaily.com/2024/11/20/stanford-students-win-cal-hacks/ | S |

### What merely existed (no win found)

| Item | What | URL | Grade |
|---|---|---|---|
| Caligo Dynamics | ROS 2 + PX4 + Kiro + Bedrock swarm, Build & Pitch w/ Raylu (Jun 2026) | https://build-pitch-w-raylu.devpost.com/project-gallery | S |
| Guardian Eye (RAVEN) | AI-coordinated ROS 2 / PX4 search-and-rescue swarm | https://devpost.com/software/guardian-eye-utd1fy | S |
| Project Pluto | Voice GCS over MAVLink; ArduPilot, not PX4 | https://devpost.com/software/project-pluto | S |
| Research stacks | "Taking Flight with Dialogue" (PX4 + ROS 2 + Ollama; best mission success 40%); PEACE (altitude / geofence constraint layer); AerialClaw; ROSA (NASA JPL); SkySim | https://arxiv.org/pdf/2506.07509 , https://arxiv.org/pdf/2606.00104 , https://arxiv.org/pdf/2606.12142 , https://arxiv.org/pdf/2410.06472 , https://arxiv.org/pdf/2602.01226 | S |
| **RIPA** (Jun 26, 2026) | Prompt injection through the sensory pipeline of an LLM-controlled ROS 2 robot: 100 runs / variant, 5 LLMs; Llama-3.3-70B 100% attack success; a hybrid semantic firewall had 0% ASR on known patterns but a 10.2% bypass rate on obfuscated attacks; LiDAR-context poisoning hit 100% on DeepSeek-V4-Flash | https://arxiv.org/abs/2606.28649 | V |
| **AgentRob** (Feb 14, 2026) | Forum agents -> MCP -> Unitree Go2/G1 robots | https://arxiv.org/abs/2602.13591 | V |
| OM1 (OpenMind); EchoPilot PX4 + Ollama + MCP | Robot HAL with LLMs (2,962 stars); voice-controlled PX4 missions | https://github.com/OpenMind/OM1 , https://github.com/Bilalileri/EchoPilot---Ollama---PX4---MCP | V |
| esp32-mcp | MCP server giving agents ESP32 relays / GPIO | https://github.com/StefanYasin/esp32-mcp | S |
| GitHub | `topic:ros2 llm` 155; "px4 llm drone" 21 | api.github.com | V |

**Observation:** the search for a winner that combines LLM + PX4 + ROS 2 + natural language returned none [S]. PX4 + ROS 2 + LLM exists mainly as papers and unjudged demos.

**Angles that read new [I]:**
- Process-control hardware (tank, pump, valve) with discrete LLM commands. Easier to make reliable than manipulation or VLA training, and unlike LeRobot-style winners it needs no demonstration data.
- Embodied injection: a printed sign / QR held up to the ROS 2 car's camera that tries to hijack it, with a geofence/speed interlock. RIPA is the research prior art; a hackathon crowd has rarely seen it live.
- Drones: PX4 SITL is common in papers (PEACE, Taking Flight); with no drone on the checkout list, a live PX4 demo is out.

**Closest prior art a judge names:** ROSA, LeRobot hackathon demos, drone-copilot, and (for security-minded judges) RIPA.

## Hardware lens (from Main's checkout list, about 4:40pm Sat)

| Item | Rig use | Novelty value | Risk |
|---|---|---|---|
| ESP32-S3 x3, Pico 2 W x7, Arduino R4 WiFi x6 | One MCU as agent gateway / process controller; a SEPARATE MCU as an independent "safety logic solver" that can cut the pump relay | Shows independence of the last layer from the LLM path (mirrors IEC 61511 BPCS vs SIS split) | Time to wire and firmware both |
| 1-ch relays, TT motors + L298N, SG90 servos | Pump, valve (servo-turned) | Real actuation: overflow, dry-run, deadhead are physical | Active-low relay boot glitches; keep to low voltage |
| 2 water-level sensors | Level readings and overflow trip | Tank-level invariant visible in 5 seconds | Only 2: one for the agent path, one for the independent layer; float switches are not on the list |
| Flame, PIR, ultrasonic, DHT11, MPU-6050 | Extra telemetry channels | Extra "embodied injection" channels | Noise |
| 2 mini projectors | Project P&ID or the attack scoreboard onto the rig | Eye-catching | Room lighting |
| Hiwonder ROS 2 mecanum car (last one; needs all team licenses) | Optional "truck" with geofence / speed interlock; sign-in-camera injection | Uses ROS 2 background; RIPA-style injection live | One unit; license overhead; time |
| Taken: Pi 5s, Pi cameras, xArm, robot dog | n/a | n/a | n/a |

## Interlock verdict

| Interlock element | Saturation | New? |
|---|---|---|
| Nemotron agent operating EOG's network | Nemotron industrial / data-center projects exist (PlantMind, AURA-OPS, Floorplan Intelligence [S]); standard for the NVIDIA track | No |
| Typed schema checks | Present in all 5 opened projects | No |
| Physical-limit checks | Caps / allowlists are universal; process-state limits are rarer | Partly |
| Ed25519-signed approvals and receipts | Table stakes (at least 10 projects, 160 repos, 4 standards) | No |
| Judges inject from a phone | Known genre (Gandalf, HackAIcon, DEF CON booths) | Hook only |
| Block shown on screen | Universal | No |
| Physical rig with an independent hardware layer | Nothing found at hackathons | **Yes [I]** |
| Automated attacker + human judges + per-layer catch counter + published rates | Partly (Agent Firewall and RIPA publish rates) | Partly |
| Receipt binding approval -> setpoint -> sensor outcome | Not found | **Maybe [I]** |

Software-only, this reads as "another agent firewall" next to Agent Firewall, Epyk Forge, SentinelPay and NVIDIA's own stack. The team's prebuilt MisaOS assets map to the saturated features, while its ROS 2 / KiCad / Raspberry Pi skills map to the thin cell [I].

## Gaps

- Most "winner" claims come from search summaries because Devpost project pages return 403; status is [S] unless marked [V].
- No Devpost totals; counts are lower bounds. Product Hunt covered only families 1-2.
- Unchecked: whether any hackathon built a sensor-bound receipt, a float-switch-style interlock, or a live judge-attack rig. Absence in about 40 queries does not prove it.
- Winners for Cal Hacks 13 (Oct 2026), HackTX 2026, and the PayPal AI Hackathon are not out.
- Industrial incumbents' product claims (Siemens, Honeywell, Cognite, Rockwell, ABB) come from one search summary each [S]; read the vendor pages before quoting any specific feature.
