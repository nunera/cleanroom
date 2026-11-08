# Cleanroom as a QEMU/KVM guest: a stock kernel, a small stage-1 initrd that mounts the host's
# /nix/store over virtio-9p (as build-vm does), and a stage-2 script that sets up the system and
# execs the init chosen at boot (dinit or s6-rc) on the services of plans/vm.json.
{
  pkgs,
  cleanroom,
  recordings,
}:
let
  inherit (pkgs) lib;
  kernel = pkgs.linuxPackages.kernel;
  busybox = pkgs.pkgsStatic.busybox;
  msize = "262144";

  modules = pkgs.makeModulesClosure {
    kernel = kernel.modules;
    firmware = pkgs.emptyDirectory;
    rootModules = [
      "virtio_pci"
      "virtio_net"
      "9p"
      "9pnet_virtio"
      "qemu_fw_cfg"
    ];
  };

  stage1 = pkgs.replaceVarsWith {
    name = "cleanroom-stage1";
    src = ./stage1.sh;
    isExecutable = true;
    replacements = {
      shell = "${busybox}/bin/sh";
      inherit busybox modules msize;
      kmod = pkgs.kmod;
    };
  };

  initrd = pkgs.makeInitrd {
    name = "cleanroom-initrd";
    contents = [
      {
        object = stage1;
        symlink = "/init";
      }
    ];
  };

  # Runs its arguments on the serial console as their controlling terminal (the TUI service).
  console = pkgs.replaceVarsWith {
    name = "cleanroom-console";
    src = ./console.sh;
    dir = "bin";
    isExecutable = true;
    replacements = {
      shell = pkgs.runtimeShell;
      path = lib.makeBinPath [
        pkgs.coreutils
        pkgs.util-linux
      ];
    };
  };

  # The service tree of plans/vm.json for each init, rendered by cleanroomd at build time.
  renderPlan =
    init:
    pkgs.runCommand "cleanroom-vm-${init}" { } ''
      ${cleanroom}/bin/cleanroomd plan render ${cleanroom}/plans/vm.json $out --init ${init}
    '';
  dinitServices = renderPlan "dinit";
  s6rcCompiled = pkgs.runCommand "cleanroom-vm-s6-rc-compiled" { } ''
    ${pkgs.s6-rc}/bin/s6-rc-compile $out ${renderPlan "s6-rc"}
  '';

  stage2 = pkgs.replaceVarsWith {
    name = "cleanroom-stage2";
    src = ./stage2.sh;
    isExecutable = true;
    replacements = {
      shell = pkgs.runtimeShell;
      path = lib.makeBinPath [
        cleanroom
        console
        pkgs.bubblewrap
        pkgs.skopeo
        pkgs.umoci
        pkgs.coreutils
        pkgs.util-linux
        busybox
        pkgs.dinit
        pkgs.s6
        pkgs.s6-rc
        pkgs.execline
      ];
      inherit
        busybox
        dinitServices
        s6rcCompiled
        recordings
        ;
      coreutils = pkgs.coreutils;
      cacert = pkgs.cacert;
    };
  };
in
pkgs.replaceVarsWith {
  name = "cleanroom-vm";
  src = ./run.sh;
  dir = "bin";
  isExecutable = true;
  replacements = {
    shell = pkgs.runtimeShell;
    qemu = pkgs.qemu_kvm;
    kernel = "${kernel}/${pkgs.stdenv.hostPlatform.linux-kernel.target}";
    initrd = "${initrd}/initrd";
    inherit stage2;
  };
  meta.mainProgram = "cleanroom-vm";
}
