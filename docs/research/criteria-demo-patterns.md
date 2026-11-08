# Demo-hook patterns, judge advice and an idea-scoring checklist (HackUTD 2026)

Written Sat 2026-11-07 by the deep-research agent. Intended path: `Tracks/research/criteria-demo-patterns.md` (Main: copy from `local://criteria-demo-patterns.md`). No other file was modified.

## Key findings

1. **Sample:** 24 first-place/overall winners at 22 events (Oct 2024 to Oct 2026) plus 28 podium/finalist projects (Hack the North 2025 and DubHacks 2025 give no single overall prize) = 52 projects (§1). Evidence quality: 7 fully verified, 6 win-verified, 11 from search extracts only.
2. **What the judge sees first** (my coding, N=24): physical artifact 38%, judge-does-something (call/play/wear/hold) 25%, verifiable artifact (PR/benchmark) 13%, visualization 13%, live effect 8%. Any-tag: judge participation 50%, live real-world effect 46%, custom hardware 42%, human story 42%, modality twist 42%, on-screen number 17%, **adversarial 0%**. Winners stack about 3 hook types each (§2).
3. **Hardware is over-represented at the top, and cheap:** 10/24 winners and 13/28 extras had custom hardware; HackGT 13's podium was 3/3 physical/AR. HackGT 12 organizer: "A physical project definitely still stands out." Winning rigs were ESP32 + load cell (Dose), ESP32-S3 + motor (Shepherd), 3D-printed LED wand + webcam (AstroDoodle). Caveats: HackUTD's last two overall winners were software, and there is no base rate of hardware among all submissions (§3).
4. **Software winners still hand the judge a verb:** call it (TalkTuahBank, FaceTimeOS), watch it act on a live feed (HawkWatch), change a price and rerun (Physical Realities), explore a 3D splat (Orca). 16/24 winners had a body or prop in the loop.
5. **Judge advice converges (§4):** lead with the problem, show something working in about 90 s, one flow, prefill and mock everything, say plainly what is live vs mocked. HackUTD's own guide: 3 min pitch + 2 min Q&A; a 2025 participant says ~2 min per judge rewards "the cover of the book".
6. **Boring in 2025-26 (§5):** chatbot clones and thin wrappers, "chat with your homework" RAG (explicit Cal Hacks 12 rubric text), look-alike LLM-ideated projects (HackGT 12: 273 submissions vs prior record 180), template reskins; "AI agent" alone is table stakes. Dashboards win small sponsor tracks, but 0/24 overall winners were plain dashboards.
7. **Novelty warning for Interlock (§6):** "LLM proposes, deterministic layer disposes" plus signed approval, kill switch and hash-chained log is already a 2026 hackathon template (IntentLock at HackRice 16; TrustMesh at VoltHacks with a simulated valve and a presenter-run "spoof attack" button; RoboSurge Lean-verified, TreeHacks 2nd; Sophi, Cal Hacks 13 1st; Shepherd's dual watchdogs). Not found anywhere: judge-driven live attacks, a physical plant behind the interlock, oilfield-specific physical limits. That gap is the differentiator, and it has zero precedent.
8. **Venue risk:** Cal Hacks 12 had no Wi-Fi; Cal Hacks 13 banned hotspots; HackUTD 2024's judging software was hacked. Local model, local AP and a fallback video are gates (§7.1).
9. **Checklist (§7):** 4 gates + 18 items scored 0-2, mapped to Novelty / Demoability / Technical and to HackUTD's rubric (Innovation, Technical Complexity, Completeness, Design, Impact, Presentation). §7.3 applies it to Interlock.

---

## 0. Legend, method, limits

| Label | Meaning |
|---|---|
| [V] | I opened a primary page stating both the win and the project (Devpost via Wayback, official news, repo README, organizer or winner post). |
| [V2] | Win confirmed on a primary page; project description comes from a search-engine extract of Devpost. |
| [S] | Only from a search-engine extract of Devpost or official pages. Devpost and its hackathon subdomains return 403/Cloudflare to fetchers. Likely right, not confirmed. |
| [INFERENCE] / [UNVERIFIED] | My reading / not confirmed anywhere. |

- **Extract reliability:** I caught three bad extracts: one cited an unrelated Hacker News thread; one described "Pause" (Edinburgh AI Hackathon 2026) as an agent firewall when it is an impulse-purchase/message nudge; one presented a 2016 PennApps win (RAMEAR) as recent. Weight [S] rows accordingly.
- **Coding:** hook codes `P J L R V H M N S A` (§2) are mine, from written descriptions. I did not watch demo videos. The "first-30-s hook" for [S] rows is inferred from the text.
- **Scale for context (submissions):** HackUTD 2025 369 (about 300 demoed, 3 h judging) [Retrograde]; Cal Hacks 12 695 [Lu]; TreeHacks 2026 378 [Peng]; HackGT 12 273 [Baweja]; HackMIT 2026 about 300 [The Tech]; Hack the North 2025 256 [UWaterloo]. MLH's 2026-season average is 1 project per 4 checked-in hackers [MLH].
- **Selection:** every 1st/overall winner I could find at the events you named (TreeHacks 2025/26, HackMIT 2025/26, Cal Hacks 11/12/13, PennApps XXVI, MHacks 2025/26, HackTX 2025/26, HackUTD 2024/25, HackGT 12/13, LA Hacks 2025/26, HackPrinceton Spring+Fall 2025, Hack the North 2025) plus HackHarvard 2025, HackIllinois 2026, DubHacks 2025. PennApps XXVII is Feb 5-7, 2027 (not yet held).

---

## 1. Winners

### 1A. First-place / overall winners (N=24)

| # | Project, event, prize | Links | Pitch | First-30-s hook (judge sees/does) | Tech | Codes | Ev |
|---|---|---|---|---|---|---|---|
| 1 | **Duet**, Cal Hacks 11 (Oct 2024), 1st overall | [page](https://devpost.com/software/duet-0tbkxe) [win](https://www.emotiv.com/blog/duet-brainwaves-music-bci-wins-calhacks-2024) | Brainwaves to live AI music for children with developmental disabilities | Wear an EEG headset; music and visuals change with your measured emotional state | Emotiv EPOC X + Cortex API, Gemini, Sonic Pi, SingleStore, Next.js | P J M H | V |
| 2 | **TalkTuahBank**, HackUTD 2024 (Nov 2024), 1st overall + Goldman 1st | [page](https://devpost.com/software/talktuahbank) [win](https://retrogradenews.com/2024/12/02/hackutd-becomes-largest-24-hour-hackathon-in-north-america-with-over-1100-attendees/) | Banking over an ordinary phone call for the unbanked | Call a normal number; the agent does balance, transfers, bill pay | Retell AI, OpenAI Swarm, Next.js, Pinata/IPFS, Python/TS | L J M H | V |
| 3 | **HawkWatch**, TreeHacks 2025 (Feb 2025), Grand Prize $11k | [archive](https://web.archive.org/web/20250930234047/https://devpost.com/software/hawkwatch) [win](https://stanforddaily.com/2025/02/18/treehacks-awards-200000-in-prizes-to-students-from-around-the-world/) | VLM turns CCTV into proactive incident alerts | Dashboard of ~15 feeds; live stream flags a person fainting and fires an email/phone alert | Gemini VLM, TensorFlow.js, Next.js, Supabase, Resend, OpenAI | L V H | V |
| 4 | **SixthSense**, HackPrinceton Spring 2025 (Mar), Best Overall | [page](https://devpost.com/software/sixthsense-xuw41r) | Assistive device that lets blind users "feel" what and where objects are | Wear it; vibration/servo patterns encode object and position [INFERENCE] | Dual Arduinos, servos, haptics, embedding-to-frequency mapping | P J H M | S |
| 5 | **Alto**, LA Hacks 2025 (Apr), 1st overall | [page](https://devpost.com/software/alto) | Find, reproduce and fix mobile bugs autonomously | Crash report in; agent writes a Maestro UI test that reproduces it and opens a fix PR [INFERENCE] | Fetch.ai uAgents, Gemini/ASI-1, Instabug/Sentry, Maestro | L R | S |
| 6 | **Colmena Maps**, HackMIT 2025 (Sep), Grand Prize (>$4k) | [CV](https://web.youwen.dev/cv/) [post](https://web.youwen.dev/writing/postscript-on-hackmit/) [code](https://code.functor.systems/youwen/colmena-maps) | Agent swarm that navigates Street View, narrated live in AR glasses | Wearer sees the agents' status and "thoughts" in sponsor-provided AR glasses while they roam | Reverse-engineered AR-glasses link, Street View, spacetime embeddings, agent swarm | P J V M | V2 (satirical retrospective) |
| 7 | **kinemo**, PennApps XXVI (Sep 2025), 1st overall | [page](https://devpost.com/software/kinemo) | Party game where your body is the controller | Two people box, slice fruit or race a reaction light at a webcam | MediaPipe, OpenCV, NumPy, Pygame | J M | S |
| 8 | **Dose**, HackGT 12 (Sep 2025), Best Overall 1st | [page](https://devpost.com/software/dose-ebmo9z) [organizer](https://www.ayushbaweja.com/blog/hackathon-vibecoding/) | Smart pill bottle that detects single pills removed | Take a pill out; the weight drop streams to a clinician dashboard in real time | XIAO ESP32-C3, TAL220 load cell + HX711, 3D-printed bottle, Next.js, Supabase | P L H | V2 (organizer says a hardware project won 1st overall; Dose named in extract) |
| 9 | **Artificial Sandwich Intelligence**, MHacks 2025 (Sep), Grand Award $4k | [page](https://devpost.com/software/artificial-gluten-intelligence) | "Not AGI, but ASI will fully autonomously make you a sandwich" | Two robot arms assemble a sandwich on the table | SO-101 bimanual arms (LeRobot), imitation learning, masked-transformer policy, Gaussian splatting | P L | S |
| 10 | **Post Surgery Pillow**, HackHarvard 2025 (Oct), 1st Best Overall | [page](https://devpost.com/software/post-surgery-pillow-psp) [news](https://www.concordiahanoi.org/connect/thunderbolt/post/~board/thunder-bolt/post/concordia-alumni-win-hack-harvard) | Sensor pillow that monitors post-op recovery | Hand the judge a pillow that tracks movement/temperature; edge ML plus Gemini triage in under 2 s | RPi + Cortex-M4 sensors, FFT, Gemini 2.5 Flash | P H S | V2 (school news confirms hardware pillow won 1st overall) |
| 11 | **AstroDoodle.party**, HackTX 2025 (Oct), Best Overall $4k | [page](https://devpost.com/software/rocket-racer-l1hmn6) | Space-racing game cast with a real wand | Judge grabs a 3D-printed LED wand and draws runes at a webcam to blow up asteroids | CAD + 3D-printed wands, OpenCV, $Q gesture matcher, Phaser 3, TS | P J M | S |
| 12 | **FaceTimeOS**, Cal Hacks 12 (Oct 2025), 1st overall | [archive](https://web.archive.org/web/20251030004408/https://devpost.com/software/facetime-macos-ai-agent) [blog](https://blog.dylanlu.com/cal-hacks-12/) [repo](https://github.com/ThePickleGawd/FaceTimeOS) | FaceTime your Mac and talk to a computer-use agent | Place a FaceTime call to a laptop; it answers, does the task, texts a screenshot as proof | Claude, Agent S3, Fish Audio + BlackHole virtual audio, Fetch.ai, Groq, Electron/Flask | J L M | V |
| 13 | **MindPad**, HackPrinceton Fall 2025 (Nov), Best Overall (co-winner) | [page](https://devpost.com/software/mindpad) | Study canvas driven by hand gestures and voice | Pan, zoom, annotate in the air at a webcam; voice agent edits the canvas | MediaPipe + ANN gesture classifier (<200 ms), OpenAI Realtime API | J M S | S |
| 14 | **Watt's Up**, HackPrinceton Fall 2025 (Nov), Best Overall (co-winner) | [page](https://devpost.com/software/watt-s-up) | Rooftop solar potential for any address | Type an address; segmented roof on satellite imagery plus payback and CO2 numbers in seconds | SegFormer-B0, Google Maps imagery, NASA POWER | V N | S |
| 15 | **Working Memory**, HackUTD 2025 (Nov), 1st Grand Prize | [page](https://devpost.com/software/working-memory) [site](https://www.workingmemory.vip/) [win](https://retrogradenews.com/2025/12/08/hackutd-marks-ten-years-of-hackathons-with-fantasy-and-fire-alarms/) | Agent that passively records coding sessions and restores context | [UNVERIFIED] start/stop a session in a dashboard; searchable timeline and summaries | VS Code MCP server, FastAPI, GitPython, OpenAI Agents SDK, React | L | V |
| 16 | **Shepherd**, TreeHacks 2026 (Feb), Grand Prize $12k | [archive](https://web.archive.org/web/20260418010348/https://devpost.com/software/raising-cane) [win](https://stanforddaily.com/2026/02/15/12th-annual-treehacks/) [code](https://github.com/tonywangs/shepherd) | Motorized smart cane at ~1/20 the cost | Hold the cane; a motorized wheel physically nudges it left/right around obstacles | iPhone LiDAR/ARKit, XIAO ESP32-S3 + DC motor, BLE 10 Hz, <50 ms; two watchdogs zero the motor | P J H S N | V |
| 17 | **Orca**, HackIllinois 2026 (Feb-Mar), Best Voyager Hack $5k | [page](https://devpost.com/software/orca-net) | Multi-agent 3D world models for emergency responders | 3D Gaussian-splat building with a fire/crisis simulation and safe-route overlay | Street View, World Labs splats, multi-agent consensus | V H | S |
| 18 | **Synapse**, HackIllinois 2026, Best General Hack $2.5k | [gallery](https://hackillinois-2026.devpost.com/project-gallery) | Beta-test signals (emotion, clicks, voice) to automatic UI-fix PRs | [INFERENCE] a flagged session turns into an opened PR | Cloudflare Workers, edge sandboxes | L R | S |
| 19 | **codebreaker**, LA Hacks 2026 (Apr), Grand Prize + Cognition 1st | [repo](https://github.com/KevinWu098/codebreaker) [page](https://devpost.com/software/codebreaker-la) | Agents detect, reproduce, validate and fix CVEs; open benchmark | [INFERENCE] vuln reproduced, then a merge-ready PR with benchmark scores | Devin, Cloudflare Workers, Modal, React/TS | R N | V2 |
| 20 | **Peel**, HackMIT 2026 (Sep), Grand Prize + Elastic challenge | [news](https://thetech.com/2026/10/01/hackmit-2026) [page](https://plume.hackmit.org/project/qxodw-wgjqk-lidau-dxrpe) | Cheap handheld lab that spots counterfeit pills | Run a pill through an LED + light-sensor dissolution test; AI evidence engine checks recalls and reference products | LEDs, light sensors, Elastic, AI evidence engine | P H L | V |
| 21 | **Sky-C2**, HackGT 13 (Sep 2026), Best Overall 1st | [page](https://devpost.com/software/sky-c2) | AR HUD for plane spotting in a phone Cardboard viewer | Look up through the viewer; callsign/altitude cards appear; ask "Hey Grok, what's that plane?" | TS/Vite (gyro), FastAPI, adsb.lol, xAI Grok | J V L M | S |
| 22 | **Physical Realities**, MHacks 2026 (Oct), Grand Prize $5k | [gallery](https://mhacks-2026.devpost.com/project-gallery) | Simulate thousands of AI humans in built spaces | Theme-park day with thousands of AI guests; change a ticket price or move a ride, rerun, compare revenue/waits/satisfaction | Desktop app, TypeSafe "Jev" decision model | V N S | V2 (winners' LinkedIn posts; no official announcement found) |
| 23 | **Sophi**, Cal Hacks 13 (Oct 2026), 1st overall | [repo](https://github.com/mzhao1599/sophi) [win](https://www.langlglang.com/) | Rolling walker with swappable robot parts, configured by talking | Push-to-talk on the handle, spoken answer, handles buzz near obstacles; website draws the walker as you speak | RPi 5, ESP32, ToF sensors, SO-101 arms/lift (sim-only at the 10/24 status), Claude, Cartesia, SpacetimeDB | P J H L | V2 |
| 24 | **Dance Fantasy**, HackTX 2026 (Oct), Best Overall | [page](https://devpost.com/software/hack-em-horns) | Upload a song to get a 3D storybook dancer; your webcam scores you | Judge dances at a webcam against a generated routine; phones join via QR | MediaPipe, librosa, Three.js, FastAPI, Gemini, TimescaleDB | J M V | S |

### 1B. Podium extras and finalists (N=28)

| Project, event, place | Link | Pitch and hook | Tech | Codes | Ev |
|---|---|---|---|---|---|
| **RoboSurge**, TreeHacks 2026, 2nd overall ($8k) | [page](https://devpost.com/software/robosurge) [author](https://justinpeng.com/) | "Cursor for surgery": language drives robot arms; LLM never computes trajectories; Lean-verified safety bounds | GPT-5.2, Gemini Robotics-ER 1.5, SAM, YOLOv11, custom IK + Runge-Kutta, RealSense, Lean, Nix | P L R H | V2 |
| **ChromaChord**, TreeHacks 2026, 3rd | [page](https://devpost.com/software/chromachord) | Play an instrument; AI accompanist follows live | MIDI/audio, 24-dim chroma vectors, harmonic graph | J M S | S |
| **Dispatch**, PennApps XXVI, 2nd | [gallery](https://pennapps-xxvi.devpost.com/project-gallery) | 911 dispatcher copilot: live transcript, urgency score, prompts | not retrieved | H S L | S |
| **OverSEA**, PennApps XXVI, 3rd | [page](https://devpost.com/software/oversear) | Satellite + AIS map of "dark" vessels | Satellite/AIS data, geospatial AI | V | S |
| **RefNet**, HackGT 12, 2nd | [page](https://devpost.com/software/refnet-c04g9n) | Citation-network explorer and literature synthesis | not retrieved | V | S |
| **vibesB2B**, HackGT 12, 3rd | [gallery](https://hackgt-12.devpost.com/project-gallery) | Emotion/engagement analytics on sales calls | not retrieved | M | S |
| **FlyBy**, HackGT 13, 2nd | [page](https://devpost.com/software/flyby-fdxcua) | Search-and-rescue drone: reflex obstacle avoidance plus LLM survivor triage | flyvis (fruit-fly connectome), Grok + Laya triage, drone | P H L | S |
| **VIGIL**, HackGT 13, 3rd | [page](https://devpost.com/software/vigil-assistive-eeywear-with-an-autonomous-aerial-scout) | Smart glasses plus companion drone scout, spatial audio | ESP32-CAM, DJI Tello, YOLO11, spiking nets | P H M | S |
| **Lumos**, LA Hacks 2025, 2nd | [page](https://devpost.com/software/lumos-f8h0mn) | AR glasses for Alzheimer's (faces, routines, navigation) | AR glasses (details not retrieved) | P H | S |
| **OpenSesame.Work**, LA Hacks 2025, 3rd | [page](https://devpost.com/software/opensesame-work) | Job discovery/application agent | not retrieved | L | S |
| **RIIS**, LA Hacks 2026, 2nd | [page](https://devpost.com/software/riis) | Disaster rover: finds survivors, triages, rebuilds the site as a 3D splat in VR | Rover, on-device CV, multi-agent triage, 3D Gaussian splatting, VR | P V H L | S |
| **Autopsy**, LA Hacks 2026, 3rd | [gallery](https://la-hacks-2026.devpost.com/project-gallery) | Causal graph of why an agent failed, fed back into its next run | not retrieved | V R | S |
| **Silent Voice**, Cal Hacks 13, 2nd + Best Use of Cartesia | [page](https://devpost.com/software/silent-voice-s1f74p) | Silent speech for laryngectomy patients; live demo over a phone call | Arduino Uno + BioAmp EMG pads (1 kHz), 45M-param SVR-1, Auto-AVSR, Claude, Cartesia streaming TTS, Twilio | P J M H L | S |
| Hack the North 2025 finalists (12 of 256 submissions; no 1st/2nd/3rd) [V2: [UWaterloo](https://uwaterloo.ca/news/eweal-making-hackathons-fun-again-breaking-guinness-world-record)]; descriptions [S]: | | | | | |
| ChessMate | [page](https://devpost.com/software/chessmate-nwygvq) | Robotic chessboard you play against | 3-DoF gantry + electromagnets, OpenCV, voice | P J M | S |
| Coach Bob! | [page](https://devpost.com/software/coach-bob) | AR warm-up game with a sensor-instrumented punching dummy | XREAL AR glasses, CV, sensors | P J V | S |
| DUM-E | [page](https://devpost.com/software/dum-e-kgx6at) | Voice-commanded robot arm picks and sorts objects | CV, homography, inverse kinematics, NLP | P M L | S |
| Lattice | [page](https://devpost.com/software/lattice-flck7q) | Live holographic point cloud | Xbox Kinect, HoloLens | P V | S |
| ROSS | [page](https://devpost.com/software/ross-42pnvi) | Robotic sketching rig with tactile and thermal output | Multi-motor rig, path generation | P M | S |
| S-KBD67 | [page](https://devpost.com/software/s-kbd67) | Nerf blaster as FPS controller | ESP microcontrollers, gyros, UDP | P J | S |
| Maatchaa / Puppeteer / Sauron / SpeakEasy / Stu3dio / Tango | [Maatchaa](https://devpost.com/software/maatchaa) [Puppeteer](https://devpost.com/software/puppeteer-7429qv) [SpeakEasy](https://devpost.com/software/speakeasy-vdkc9n) [Tango](https://devpost.com/software/tango-q37d4z) | Software finalists: creator matching; fake backend for frontend devs; device-trajectory map (Sauron); mock-interview coach; 3D AI movie studio (Stu3dio); macOS voice agent. Sauron and Stu3dio URLs not confirmed | Shopify + embeddings; multi-model LLM routing; Mapbox; MediaPipe; video generation; VAD + LLM routing | R V J M | S |
| DubHacks 2025 title-track winners (no overall prize), [S]: **Math Sandbox** (INVENT) | [page](https://devpost.com/software/interactive-grapher-thingy) | Camera + projector turn handwritten equations on paper into projected graphs | Camera, projector, OpenCV, Gemini | P V J | S |
| **Artemis** (GROW) / **Chameleon** (NEXT) | [Artemis](https://devpost.com/software/artemis-kxd36i) [Chameleon](https://devpost.com/software/robyn-6i4v2u) | Eye-tracking focus assistant; head-tracking and voice web navigation | Eye/head tracking, voice | M | S |

### 1C. Sponsor-track winners relevant to your tracks (not counted in stats)

| Project, event | Link | What it shows | Ev |
|---|---|---|---|
| **Toyotron**, HackUTD 2025 NVIDIA 1st + Toyota Financial 1st | [page](https://devpost.com/software/toyotron) | Web chat plus a real phone call, multi-agent tool use (Nemotron 49B, Retell, Calendar). Copied the 2024 winner's shape | V (prior research) |
| **Guido**, HackTX 2025, Northmark prize | [Northmark post](https://nmc2.com/how-hacktx-25-showcased-the-future-of-ai-driven-decision-making/) | 1,000 F1 races simulated in 5 s (186/s) with an "opportunity cost" view: the sponsor singled out speed and compute | V |
| **PipeBrAIns / DHy-n0**, HackUTD 2024 EOG | [PipeBrAIns](https://devpost.com/software/pipebrains) | ML on EOG's own data plus dashboard and alerts; no LLM | V (prior research) |
| **Nomi**, AWS x NVIDIA Agentic AI Unleashed, grand prize | [updates](https://nvidia-aws.devpost.com/updates) | Multi-sensor network plus Nemotron-Nano agent for senior living | S |
| **Code Canary**, Lux Capital AI Agent & Infra Hackathon, 1st overall | [listed here](https://tonywang.xyz/projects.html) | SBOM and vulnerability-triage agent | V2 |

---

## 2. Hook taxonomy and counts

Codes are not exclusive. "Primary" is the single feature a judge would describe afterwards (mutually exclusive). Primary counts sum to 23 plus Working Memory, whose hook is unverified.

| Code | Hook | What the judge sees or does | GP primary (N=24) | GP any (N=24) | Extras any (N=28) | Best exemplars |
|---|---|---|---|---|---|---|
| P | Physical/hardware action | A thing on the table moves, senses, buzzes or lights up | 9 (38%) | 10 (42%) | 13 (46%) | Shepherd, Dose, Sophi, ASI, Peel |
| J | Judge/audience participation | Judge calls, texts, plays, wears or holds | 6 (25%) | 12 (50%) | 7 (25%) | FaceTimeOS, kinemo, AstroDoodle, Dance Fantasy, Sky-C2 |
| L | Live real-world effect | A call, alert, PR or robot motion really happens | 2 (8%) | 11 (46%) | 7 (25%) | TalkTuahBank, HawkWatch, Alto |
| R | Verifiable artifact | Merge-ready PR, benchmark, proof | 3 (13%) | 3 (13%) | 3 (11%) | codebreaker, Alto; RoboSurge (Lean) |
| V | Spectacle visualization | 3D splat, AR HUD, map, graph | 3 (13%) | 7 (29%) | 9 (32%) | Orca, Physical Realities, Sky-C2, RIIS |
| H | Human story | Blind users, patients, elderly, disaster | 0 (framing) | 10 (42%) | 7 (25%) | Shepherd, Duet, Sophi, Dose |
| M | Modality twist | Input/output is not a text box: FaceTime, EEG, body, AR glasses | 0 | 10 (42%) | 10 (36%) | FaceTimeOS, Duet, kinemo |
| N | Before/after or on-screen number | $, benchmark, side-by-side sim | 0 | 4 (17%) | 0 | Physical Realities, Shepherd, codebreaker |
| S | "Impossible" speed or scale | <50 ms, 1,000 sims in 5 s, thousands of agents | 0 | 4 (17%) | 2 (7%) | Shepherd, PSP, MindPad; Guido (sponsor track) |
| A | Adversarial/live attack | Judge attacks the system | 0 | **0 (0%)** | **0** | None found. Nearest: TrustMesh's "Simulate Sensor Spoofing Attack" button (presenter-run, no win claimed) |

Observations (all [INFERENCE] from my coding unless cited):
- **A body or prop in the loop (P or J) = 16/24 (67%).** The other 8 are screen-only (HawkWatch, Alto, Watt's Up, Working Memory, Orca, Synapse, codebreaker, Physical Realities); each still has a visible action or a rerunnable simulation.
- **Mean about 3 codes per winner; 16/24 stack three or more.** Shepherd stacks P J H S N; Sophi P J H L; Duet P J M H. Single-hook winners are rare.
- **By year, hardware share of 1st places:** 2025 6/13; 2026 3/9 (4/9 counting Sky-C2's Cardboard rig). Podiums: HackGT 13 3/3 physical/AR; TreeHacks 2026 2/3 (Shepherd, RoboSurge); LA Hacks 2026 1/3 (RIIS 2nd); Hack the North 6/12 finalists.
- **Three codes you named never lead:** before/after counter, "impossible" speed/scale and adversarial attack are supporting hooks at best (0 primary). They add value as overlays on a physical or participatory lead.
- **Base-rate caveat:** I sampled winners only. Hardware's share of all submissions is unknown (the HackGT 12 organizer gives no counts, only that hardware-track teams still treated time as a constraint), so I cannot say hardware wins more often per entry.

---

## 3. Physical and tabletop demos: what the evidence supports

Prompted by Main's hardware list (ESP32-S3 x3, Pico 2 W, Uno R4, SG90 servos, L298N, relay, two water-level sensors, LEDs/buzzers, two mini projectors, 3D printing; Pi 5s and cameras taken).

| Precedent | Rig | Signal for a small ESP32 rig |
|---|---|---|
| Dose, HackGT 12 1st | XIAO ESP32-C3 + load cell + HX711 + 3D-printed bottle; 4-person split (hardware / firmware / dashboard / DB) | A one-sensor "physical event to live dashboard" loop won overall |
| Shepherd, TreeHacks 2026 1st | XIAO ESP32-S3 + DC motor + BLE + phone LiDAR; iOS 500 ms frame watchdog and ESP32 250 ms packet timeout "independently zero the motor" | Your exact MCU; the safety interlock was itself a physical fail-safe |
| AstroDoodle, HackTX 2025 1st | 3D-printed wand (2xAAA + LED) + webcam, 24 h | A cheap prop the judge holds beats a complex rig |
| Post Surgery Pillow, HackHarvard 1st | Home Depot materials; team had "limited experience with hardware construction"; competitors "mostly software" ([news](https://www.concordiahanoi.org/connect/thunderbolt/post/~board/thunder-bolt/post/concordia-alumni-win-hack-harvard)) | Hardware experience is not required; scarcity is the edge |
| Sophi, Cal Hacks 13 1st | Pi 5 + ESP32 + ToF; its own [status page](https://raw.githubusercontent.com/mzhao1599/sophi/main/docs/demo/tracks.md) (10/24): "Nothing has moved a real arm or the lift"; README: cloud "can never move a motor, skip a stop, or silence an obstacle alert" | It won with only parts of the rig live. One or two real physical beats mattered, not completeness. Honest status labelling did not hurt [INFERENCE] |
| Math Sandbox, DubHacks 2025 INVENT winner [S] | Camera + projector + paper | Matches your two mini projectors: project the plant schematic or live state onto a printed map |
| Silent Voice, Cal Hacks 13 2nd [S] | ~$20 EMG pads + Arduino Uno | Sub-$50 sensors reach the podium; the live demo was a phone call |

- **Extra prize slot:** the team may add one HackUTD track on top of three sponsor tracks: Best Hardware, Best Design or Virality ([materials.md](materials.md), Devpost rules). Cal Hacks 12's equivalent prize was a 3D printer ([prizes](https://live.calhacks.io/prizes)).
- **Organizer view (HackGT 12):** "Hardware is Still, Hard ... the AI tools for hardware are not there yet." Hardware teams "still seemed to consider time a limiting constraint" ([Baweja](https://www.ayushbaweja.com/blog/hackathon-vibecoding/)). Budget one dedicated hardware owner.
- **Caution:** HackUTD's last two overall winners (TalkTuahBank 2024, Working Memory 2025) and its NVIDIA winner (Toyotron) were software. Most hardware evidence comes from other schools' events [INFERENCE: judge pools and maker culture differ]. Treat hardware as the lead hook, not a substitute for the sponsor-track story.
- **Fit to Main's inventory [INFERENCE]:** the list has no pump or solenoid valve. Feasible actuators are a servo-turned valve lever, a relay-switched load, and an LED tower (green/amber/red) plus buzzer for the interlock trip; the two level sensors give a real "tank high/low" signal. Verify what is actually on hand before committing.

---

## 4. Judge and organizer advice (2024-2026)

| Source (role, date) | Quote or finding | Link | Implication |
|---|---|---|---|
| Katherine Druckman, JetBrains blog on JetBrains x Codex Hackathon judges, Jun 2026 | "A strong project with a confusing demo loses to a simpler project that the judges understand." | [post](https://blog.jetbrains.com/ai/2026/06/how-to-win-a-hackathon-notes-from-the-judging-table/) | Clarity beats depth |
| Jono Bacon (Stateshift), same post | Get judges "sharing your frustration with the problem that you see in the world"; show something working within about 90 seconds (author's paraphrase) | same | Problem first, hook by 90 s |
| Avi Press (Scarf), same | "Put the judge in the shoes of the user and walk them through what happens." Be "very direct about what works, what doesn't" | same | Honest live/mock labels |
| Bonnie Xu (OpenAI), same | Ask "what's something I can build now that I probably couldn't have built before?" | same | The "why now" line |
| Colin Lowenberg (Nebius), same | "Mock everything you can and make sure all your forms are filled" | same | Prefill, remove stalls |
| Devpost, 5 judges (Google, Databricks, Atlassian, Square, NEAR), image dated Oct 2024 | Karen Bajza-Terlouw: "Ambiguity is a red flag, and also projects that lack detail and code." Kelvin Boateng: standouts "depart the most from that template." Warren Marusiak penalizes "rehashed ideas." Maria Yarotska: the same project "with a different label" is a red flag | [post](https://info.devpost.com/blog/hackathon-judging-tips) | Differentiate; judges open the repo |
| HackUTD Tech Guide (2025) | "Great projects do not always win. Great presentations can make the difference." 3 min pitch + 2 min Q&A. Pick a "visually compelling" Devpost thumbnail, video under 2 min, memorable name | [guide](https://guide.hackutd.co/Workshops/Pitching/) | Your own organizers' rules |
| MLH Judging Plan, 2026 season | Recommends science-fair judging; judges get "only 3 minutes per team"; stack ranking (each judge's top 3 score 3/2/1); hackers who "spent their time creating a product rather than awesome technology" rarely win | [guide](https://guide.mlh.com/general-information/judging-and-submissions/judging-plan) | If HackUTD stack-ranks [UNVERIFIED], a memorable top-3 beats a well-rounded 4th |
| Dylan Lu, Cal Hacks 12 grand prize and judge, Nov 2025 | "I recently judged for a hackathon at ASU and almost every project was just a chatbot clone. Super boring." "Have a guy primarily focus on the UI and demo"; keep "a hardcoded fallback"; build "something cooler than the last year's winner" | [blog](https://blog.dylanlu.com/cal-hacks-12/) | Direct winner-and-judge evidence; he removed fragile clicking from the demo |
| Ayush Baweja, HackGT 12 ops director, Nov 2025 | 273 submissions vs prior record 180; "a lot of the projects I saw had really similar ideas"; "A physical project definitely still stands out"; best agents "used agents in new interfaces" | [post](https://www.ayushbaweja.com/blog/hackathon-vibecoding/) | LLMs flooded the field with look-alikes; physical and new interfaces stand out |
| Retrograde on HackUTD 2025, Dec 2025 | About 2 min per judge; participant: judges "judge it solely based on the cover of the book"; NVIDIA's Alexiuk: show it "isn't just entry 17 out of 38 on your resume"; stories "born from personal need" | [article](https://retrogradenews.com/2025/12/08/hackutd-marks-ten-years-of-hackathons-with-fantasy-and-fire-alarms/) | Your venue, your sponsor: first impression and personal stakes |
| Ryan Gariepy (Rockwell), Hack the North 2025 judge; co-director Jasmine Jiang | "They weren't building business pitch decks. They were solving problems." Organizers: "hackathons just aren't fun anymore" | [UWaterloo](https://uwaterloo.ca/news/eweal-making-hackathons-fun-again-breaking-guinness-world-record) | Playfulness and real problems read well |
| Cua (HTN sponsor), Sep 2025 | Entries "clustered around the safe pick"; wants "a private eval set for judging" and to "reward generalization, not lucky runs" | [blog](https://cua.ai/blog/hack-the-north) | Matches EOG's unseen `test/` network: generalization is the score |
| Harry Westworth (Knowunity judge), HackLondon 2026 | "A judge sees only the problem you chose, the experience you made and the story you can demonstrate." | [blog](https://harrywestworth.me/blog/knowunity-hacklondon-2026/) | Demo the problem, not the stack |
| Stanford Daily on TreeHacks 2026; The Tech on HackMIT 2026 | TreeHacks judges on "creativity, technological complexity and social impact"; HackMIT on "originality, technical complexity, and collaboration", ~15 teams advance after round one | [TreeHacks](https://stanforddaily.com/2026/02/15/12th-annual-treehacks/) [HackMIT](https://thetech.com/2026/10/01/hackmit-2026) | Rubrics reward novelty plus complexity plus stakes |
| John Detter (Spacetime), MHacks 2026 judge, Oct 2026 | Looked for Spacetime "central to the experience, not just an extra chat feature"; "Demo videos were especially helpful" | [recap](https://spacetimedb.com/blog/a-weekend-at-mhacks) | Sponsor tech must be load-bearing |
| Cal Hacks 12 sponsor rubrics | Fetch.ai: Functionality 25%, Technology use 20%, Innovation 20%, Impact 20%, UX/presentation 15%. Baseten: "Technical sophistication -- not a wrapper" | [prizes](https://live.calhacks.io/prizes) | Typical agent-track weighting |
| HackUTD 2026 rules | Judging criteria: Innovation, Technical Complexity, Completeness, Design, Impact, Presentation; AI encouraged but "the idea must be yours"; science-fair style | [logistics.md](logistics.md) (Devpost rules) | Map your three criteria onto these (§7) |

---

## 5. AI-era generic ideas judges now find boring

| Archetype | Evidence | Strength | Nuance |
|---|---|---|---|
| Chatbot clone / thin LLM wrapper | Dylan Lu (judge, ASU): "chatbot clone. Super boring." Cal Hacks 12 Baseten rubric: "not a wrapper." HackLondon brief "deliberately bigger than an AI wrapper." HackUTD 2024 EOG winner PipeBrAIns wrote that "most competition simply use wrappers such as GPT" (prior research) | Strong: 4 independent sources, 2024-26 | None found in the other direction |
| "Chat with your homework" RAG app | Same Baseten rubric: "Originality -- not a chat with your homework rag app" | Medium: one sponsor rubric | Explicit, written, at the hackathon you most resemble (Cal Hacks) |
| Look-alike submissions from LLM ideation and track funneling | HackGT 12: 273 vs 180 prior record; "really similar ideas"; sponsor tracks "caused a lot of similar projects" | Medium: one organizer | Applies to HackUTD's sponsor briefs too [INFERENCE] |
| Template reskin / same project relabeled | Devpost judges (Boateng, Yarotska) | Medium | Judges check Devpost history |
| "AI agent" as the pitch | HackMIT 2025 grand-prize team: the "AI agents space was oversaturated with corporate slop" (satirical post); Baweja: agents are "the natural transition from when every project was a chatbot"; Lu: no "AI agent" and a project "doesn't produce enough dopamine" | Medium | Agent-ness is table stakes. The twist (interface, hardware, hook) differentiates |
| Dashboard-only analytics | HackUTD 2025 T-Mobile: all 3 winners were sentiment dashboards from 53 entries (prior research); Retrograde reports a participant's view that two-minute judging "would almost always lead to flashy user interfaces winning" | Weak to medium | Dashboards win small sponsor tracks. 0/24 overall winners were plain dashboards; HawkWatch is the closest, with live VLM detection and alerts |
| Car-finder / finance / voice-banking agents at HackUTD | Toyotron copied TalkTuahBank and still won (prior research) | Medium, local | Over-copied shape means more clones in 2026 [INFERENCE] |
| "AI tutor" | No judge in a source I could open calls it boring. HackLondon's 21-team learning track was won by a tutor with Manim visuals, ElevenLabs voice and ADHD/dyslexia support; HackMIT 2026 education track went to Burrow (Socratic study bunny) | Weak | Tutors win track prizes when differentiated; none of the 24 overall winners was one [INFERENCE] |
| Instant AI-coded prototypes | A May 2026 participant report: 15 of 15 teams had working prototypes in five hours, and the agent had fabricated the data ([post](https://www.unsubmittedblog.com/p/i-went-to-an-ai-hackathon-heres-what)); Devpost judge: slick video, "lighter on code" | Weak | A working prototype no longer differentiates; show real data and real hardware |
| Travel planner, resume optimizer, mood companion | Appear on listicles with no primary source | [UNVERIFIED] | Do not rely on these |

---

## 6. Saturation check for Interlock's architecture

| Entry | Event | What it does | Win? | Overlap with Interlock | Gap |
|---|---|---|---|---|---|
| **TrustMesh** | VoltHacks 2026 | Gemini proposes valve commands; plain-TS policy engine (envelope, slew-rate, anti-spoof); SHA-256 hash-chained log; "Simulate Sensor Spoofing Attack" button. "The AI proposes. The physics decides." Valve and telemetry simulated ([README](https://github.com/Shital2108/trustmesh)) [V] | None claimed | Very high: schema, physical-limit checks, audit chain | Presenter-run attack, no hardware, no signed approvals |
| **IntentLock** | HackRice 16 / "Rice Hackathon 2026" (Sep 2026) | Default-deny policy engine outside the LLM (11 checks); WebAuthn passkey approval bound to the action's SHA-256; kill-switch epoch; signed hash-chained log; harness runs 10 attacks ([author](https://www.bek-sam.dev/)) [V] | Persona-challenge win [S, unverified: author's awards list omits it] | Very high: signed approvals gating actions | No physical plant; attacks run by a harness, not judges |
| **RoboSurge** | TreeHacks 2026, 2nd | LLM never computes trajectories; Lean-verified safety bounds [V2] | Yes | High: verification under an LLM, physical robot | Surgery domain; no adversarial participation |
| **Sophi** | Cal Hacks 13, 1st | Cloud cannot move motors; Pi enforces limits; lift firmware stops after 300 ms without a heartbeat; a latching hardware stop is specified but, per its 10/24 status doc, not wired; firmware tested on a computer only [V2] | Yes | High for the "model proposes, local safety disposes" story | Mobility aid; no attack theatre |
| **Shepherd** | TreeHacks 2026, 1st | Dual watchdogs zero the motor [V] | Yes | Medium | Safety is a footnote, not the demo |
| **Agentware 2026** | Hackathon Raptors, Nov 27-30, 2026 (not yet held) | "Best Kill Switch" award, hostile "Trap Pack" inputs, judges run your agent against them [S] | n/a | Shows organizers asking for guardrail demos | Automated, not live |
| **Pause** | Edinburgh AI Hackathon 2026, 1st [S] | Impulse-purchase and message nudges | Yes | **None.** Not an agent-safety project despite the name | n/a |

[INFERENCE] The architecture is no longer novel by itself, and judges at top events have just rewarded it. What I could not find in 52 projects or the searches above: judge-driven live attack as the hook (A = 0), a safety layer in front of a physical produced-water process, and EOG-derived limits with signed approvals gating a real actuator. These are the differentiators. They are also unproven with judges, so test them early.

---

## 7. Scoring checklist

### 7.1 Gates (fail any: redesign before building)

| Gate | Test | Evidence |
|---|---|---|
| G1 | A hook fires within 30 s and a working result within 90 s | JetBrains judges; HackUTD guide; MLH |
| G2 | Runs on one laptop plus rig with no venue Wi-Fi, and a recorded fallback exists | Cal Hacks 12 had none (Lu); Cal Hacks 13 banned hotspots (Sophi doc); HackUTD 2024 judging software was hacked |
| G3 | One flow fits 3 min pitch + 2 min Q&A, and a stranger can repeat it in a sentence | HackUTD guide; Devpost judges |
| G4 | Nothing in the demo path is silently faked; mocks are labelled | Devpost judges; Avi Press (JetBrains post); Sophi status page |

### 7.2 Scorecard (0 / 1 / 2 each; 36 max; thresholds are my heuristic)

| ID | Criterion | 0 | 1 | 2 | Basis |
|---|---|---|---|---|---|
| **Novelty** | | | | | |
| N1 | Not a wrapper/RAG/dashboard | Chat box or dashboard is the product | Tools act, but only on screen | Output changes something outside the screen; chat optional | §5 |
| N2 | Distinct from 2025-26 winners and from the policy-engine template | You can name a same-shape winner | Same shape, new twist | 5-minute Devpost + GitHub search finds nothing with the same hook and domain | Lu "cooler than last year"; §6 |
| N3 | Domain-real | Generic | Sponsor domain named | Limits and numbers come from the sponsor's data; a domain person would nod | NVIDIA "personal need"; Peel, Dose |
| N4 | Modality twist | Text in, text out | Voice or phone | Body, prop, device or call in; non-screen out | 10/24 M |
| N5 | "Couldn't build this before" | None | Vague | One sentence a stranger repeats | Bonnie Xu |
| **Demoability / flashiness** | | | | | |
| D1 | 30-s hook visible from 3 m | Needs explaining | Visible after 30-60 s | Something moves, lights or speaks, or a judge acts, within 30 s | §2 |
| D2 | Judge verb | Watch only | Presenter drives, judge asks | Judge calls, texts, plays, wears or pushes within 20 s | 12/24 J |
| D3 | Physical or projected artifact | Laptop only | Prop, LED or phone display | Working rig on the table | 10/24 P |
| D4 | A moving number | None | Static stat | Live counter ($, latency, % blocked) | Shepherd, Guido, Physical Realities |
| D5 | Packaging | Default UI | Clean UI | UI/demo owner, memorable name, thumbnail, video under 2 min | HackUTD guide; Lu |
| D6 | Human stake in one sentence | None | Abstract | Named person or harm | 10/24 H |
| D7 | Survives judge improvisation | Crashes on odd input | Recovers by restart | Reset in under 5 s, rate-limited, sane defaults | Lu fallback; Devpost "happy path" advice |
| **Technical impressiveness** | | | | | |
| T1 | Real integration | Mocks | Partly live | Core path live; mocks labelled | Sophi tracks.md; Devpost judges |
| T2 | Deterministic or verified core, LLM as one part | Prompt only | Schema validation | Invariants or proofs with a test judges can see | RoboSurge, Sophi, TrustMesh |
| T3 | Measured numbers | None | Anecdotal | Latency/accuracy/pass-rate shown | Shepherd <50 ms; Guido; codebreaker |
| T4 | Visible multi-step tool use | Single call | Multi-step but hidden | Live trace with tool calls and receipts | NVIDIA brief; Toyotron |
| T5 | Repo and reproducibility | Private/messy | Public README | Public repo, architecture diagram, one-command run | Devpost judges |
| T6 | Named hard problem | None | Generic | The hardest part, how you solved it, rehearsed for Q&A | Devpost "hardest challenge" question |

Reading it: 30-36 strong; 24-29 viable if gates pass; under 24 rework or drop [INFERENCE]. HackUTD rubric mapping: Innovation = N; Technical Complexity = T; Completeness, Design, Presentation = D; Impact = N3/D6.

### 7.3 Applying it to Interlock [INFERENCE]

- **Strong:** T2 (typed records, Ed25519-signed approvals, bubblewrap, receipts are at least comparable to IntentLock's passkey-bound approvals and richer than TrustMesh's simulated engine); N3 (EOG limits from EOG's data); D4 (the EOG research derives a real before/after: do-nothing about $12,241 vs optimal about $3,108 in the snapshot case; see `domain-eog.md`); G2 (local model).
- **Highest-value D1+D2+D3 stack:** a tabletop tank on an ESP32-S3 (two level sensors, relay or servo valve, LED tower, buzzer) plus judges texting injections from their phones. Closest precedents: FaceTimeOS and TalkTuahBank (message or call the agent), AstroDoodle and kinemo (judge plays), Shepherd and Dose (cheap ESP32 rigs). That is P + J + A + L + N + H, six codes vs the winners' mean of about 3.
- **Main novelty risk (N2):** TrustMesh and IntentLock already show the architecture. Lead with the judge attack and the physical consequence, not with "policy engine."
- **A = 0 precedent cuts both ways:** judges may not try attacks. Offer a one-tap attack menu plus free text on a QR page, a visible attempt counter, the reason code on screen, and a presenter-run attack as fallback (TrustMesh's button).
- **Network risk:** judges' phones need a path to the rig. Plan a local AP/QR or a laptop at the table; do not depend on venue Wi-Fi (G2). Photon/iMessage needs Apple devices.
- **Extra prize:** a physical rig makes the HackUTD Best Hardware slot realistic (§3).

### Recommendation

Keep Interlock only if both the physical rig and the judge-driven attack loop make the demo path, with at least two physical beats working live (level reading and valve or interlock trip). Then lead with the judge action, show the dollar number from EOG's data as the overlay, and rehearse a 30-second opener plus a recorded fallback. If the rig slips, fall back to a simulated plant with a presenter-run attack (TrustMesh-style) and expect N2 and D3 to score low.

---

## 8. Gaps and what to verify in a browser

- All [S] rows rest on search extracts. Open the Devpost galleries to confirm prize tiers: `hackgt13.devpost.com`, `hacktx26.devpost.com`, `mhacks-2026.devpost.com`, `cal-hacks-13-0.devpost.com`, `hackprinceton-fall-2025.devpost.com`, `hackillinois-2026.devpost.com`, `pennapps-xxvi.devpost.com`.
- MHacks 2026 grand prize rests on the winners' LinkedIn posts via a search extract; no official announcement found.
- IntentLock's and TrustMesh's wins are unverified. Pause's win is [S].
- Hooks are inferred from text, not video. I did not find judge statements calling "AI dashboards" or "AI tutors" boring in any page I could open (Reddit threads were blocked).
- HackMIT 2025 runners-up, TreeHacks 2025 runners-up, PennApps XXV and HackPrinceton Spring 2026 were not collected.
- HackUTD's actual scoring method (stack ranking or rubric sums) and time per demo are [UNVERIFIED].
