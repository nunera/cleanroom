#!@shell@
# Stage 1 (/init of the initrd): load the virtio, 9p and fw_cfg modules, build a tmpfs root with the
# host's /nix/store mounted read-only over 9p, and switch_root into the stage-2 script named on the
# kernel command line (cleanroom.stage2=/nix/store/...). The initrd itself stays small: busybox,
# kmod and the module closure. @busybox@, @kmod@, @modules@ and @msize@ are substituted at build time.
# kmod first: busybox's modprobe has no -d and cannot read the xz-compressed modules.
export PATH=@kmod@/bin:@busybox@/bin

fail() {
  echo "cleanroom stage 1: $*; dropping to a shell" >&2
  exec sh
}

mkdir -p /proc /sys /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

stage2=
for arg in $(cat /proc/cmdline); do
  case $arg in
    cleanroom.stage2=*) stage2=${arg#cleanroom.stage2=} ;;
  esac
done
[ -n "$stage2" ] || fail "no cleanroom.stage2= on the kernel command line"

for module in virtio_pci virtio_net 9p 9pnet_virtio qemu_fw_cfg; do
  modprobe -d @modules@ "$module" || fail "cannot load kernel module $module"
done

# The new root is a tmpfs, not the initramfs rootfs: pivot_root (bubblewrap) refuses to run on rootfs.
mkdir -p /newroot
mount -t tmpfs -o mode=0755 root /newroot || fail "cannot mount the root tmpfs"
mkdir -p /newroot/nix/store /newroot/proc /newroot/sys /newroot/dev
mount -t 9p -o trans=virtio,version=9p2000.L,cache=loose,msize=@msize@,ro nixstore /newroot/nix/store ||
  fail "cannot mount the host /nix/store (9p tag nixstore)"
[ -x "/newroot$stage2" ] || fail "stage 2 $stage2 is not in the shared store"

mount --move /proc /newroot/proc
mount --move /sys /newroot/sys
mount --move /dev /newroot/dev
exec switch_root /newroot "$stage2"
