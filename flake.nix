{
  description = "Cleanroom: a responder OS where Nemotron agents work incidents inside verifiable, signed strata";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            # Rust
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            cargo-deb

            # Strata: fetch, verify and unpack roots, then sandbox them
            bubblewrap
            skopeo
            umoci

            # Scenario and debugging
            jq
            yara

            # Demo session (scripts/demo.sh)
            tmux
          ];
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
          # Host nix-ld paths in LD_LIBRARY_PATH make nixpkgs cargo load a newer host libcurl and crash.
          shellHook = "unset LD_LIBRARY_PATH";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
