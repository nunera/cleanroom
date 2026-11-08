# Cleanroom

When an attacker owns your network, the first thing you can't trust is your own tools.

Cleanroom is a responder OS for cyber incidents. Every tool, Linux root and agent environment is declared, pinned by digest and admitted by signature before it runs. Nemotron agents investigate inside sandboxed strata, each with only the access its role needs, and a ratatui command center shows the incident, the scope of compromised data and the legal notification clocks as they unfold.

Built at HackUTD 2026 (ZeroDay) for the NVIDIA and Winstead tracks.

## Status

Early. The shared wire contract (`crates/proto`, [docs/interfaces.md](docs/interfaces.md)) is in place; the daemon, agents and TUI are being built now.

## Layout

| Path | What |
| --- | --- |
| `crates/proto` | Wire types shared by the daemon, agents and TUI |
| `docs/interfaces.md` | Transport, signing, receipts, daemon operations, grants |
| `docs/concept.md` | What we're building and why |
| `docs/research/` | Research notes behind the design |

## Develop

```sh
nix develop
cargo check
```

## Prior work

Cleanroom rebuilds ideas from [MisaOS](https://github.com/nunera/misaos) (strict records, signed local admission of digest-pinned roots, sandboxed foreign roots, Nix packaging). The Cleanroom code itself is written at the event.

## License

Apache-2.0
