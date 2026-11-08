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
      # What the Rust build and its tests read: the workspace, the policy and plans compiled in or
      # checked by tests, and the scenario, root locks and nixpkgs pin cleanroomd ships with.
      src =
        with nixpkgs.lib.fileset;
        toSource {
          root = ./.;
          fileset = unions [
            ./Cargo.toml
            ./Cargo.lock
            ./crates
            ./policy
            ./plans
            ./scenario
            ./roots
            ./flake.lock
          ];
        };
      # The committed LLM recording the VM replays; kept out of src so it doesn't rebuild the Rust.
      recordings = builtins.path {
        path = ./recordings;
        name = "cleanroom-recordings";
      };
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          # The canary ransomware runs inside the admitted Debian root, where no Nix store
          # libraries exist, so it is linked statically.
          ransom = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
            pname = "cleanroom-ransom";
            inherit version src;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "-p"
              "cleanroom-ransom"
            ];
            doCheck = false;
          };
          cleanroom = pkgs.rustPlatform.buildRustPackage {
            pname = "cleanroom";
            inherit version src;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "-p"
              "cleanroom-daemon"
              "-p"
              "cleanroom-agents"
              "-p"
              "cleanroom-tui"
            ];
            cargoTestFlags = [
              "-p"
              "cleanroom-daemon"
              "-p"
              "cleanroom-agents"
              "-p"
              "cleanroom-proto"
            ];
            # roots::tests copies a local OCI image with skopeo and umoci; the router test builds
            # an HTTPS client, which needs a CA bundle the build sandbox doesn't have.
            nativeCheckInputs = with pkgs; [
              cacert
              skopeo
              umoci
            ];
            nativeBuildInputs = [ pkgs.makeWrapper ];
            # cleanroomd finds its repository as the nearest ancestor of its binary holding
            # scenario/ and roots/, so the package carries them next to bin/.
            postInstall = ''
              cp -r scenario roots plans policy flake.lock $out/
              wrapProgram $out/bin/cleanroomd \
                --prefix PATH : ${
                  pkgs.lib.makeBinPath (
                    with pkgs;
                    [
                      bubblewrap
                      skopeo
                      umoci
                    ]
                  )
                } \
                --set-default CLEANROOM_RANSOM_BIN ${ransom}/bin/cleanroom-ransom
              wrapProgram $out/bin/cleanroom-agents \
                --set-default SSL_CERT_FILE ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
            '';
            meta = {
              description = "Cleanroom OS core (cleanroomd) and the Nemotron agent team (cleanroom-agents)";
              license = pkgs.lib.licenses.asl20;
              mainProgram = "cleanroomd";
            };
          };
          # Bootable QEMU/KVM guest running plans/vm.json: nix run .#vm -- [--init dinit|s6-rc] [--live]
          vm = import ./vm { inherit pkgs cleanroom recordings; };
        in
        {
          inherit cleanroom ransom vm;
          default = cleanroom;
        }
      );

      apps = forAllSystems (pkgs: {
        cleanroom = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.cleanroom}/bin/cleanroomd";
        };
        agents = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.cleanroom}/bin/cleanroom-agents";
        };
        vm = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.vm}/bin/cleanroom-vm";
        };
        default = self.apps.${pkgs.stdenv.hostPlatform.system}.cleanroom;
      });

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
