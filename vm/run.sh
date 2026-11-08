#!@shell@
# cleanroom-vm [--init dinit|s6-rc] [--live] [--mem 4G]: boot Cleanroom under QEMU/KVM with the
# services of plans/vm.json and the command center on this terminal (the serial console).
# Ctrl-a x quits QEMU.
set -euo pipefail

init=dinit
live=0
mem=4G
while (($#)); do
  case $1 in
    --init) init=${2:?--init needs dinit or s6-rc}; shift ;;
    --live) live=1 ;;
    --mem) mem=${2:?--mem needs a size such as 4G}; shift ;;
    -h | --help) sed -n '2,4s/^# \{0,1\}//p' "$0"; exit 0 ;;
    *) echo "cleanroom-vm: unknown flag $1" >&2; exit 2 ;;
  esac
  shift
done
case $init in
  dinit | s6-rc) ;;
  *) echo "cleanroom-vm: --init must be dinit or s6-rc, not $init" >&2; exit 2 ;;
esac

rows=24
cols=80
if size=$(stty size 2>/dev/null) && [[ $size =~ ^([0-9]+)\ ([0-9]+)$ ]] && ((BASH_REMATCH[1] > 0)); then
  rows=${BASH_REMATCH[1]}
  cols=${BASH_REMATCH[2]}
fi
term=${TERM:-xterm-256color}
[[ $term == dumb ]] && term=xterm-256color

append="console=ttyS0 quiet cleanroom.stage2=@stage2@ cleanroom.init=$init"
append+=" cleanroom.rows=$rows cleanroom.cols=$cols cleanroom.term=$term"
extra=()
if ((live)); then
  secret=${XDG_CONFIG_HOME:-$HOME/.config}/cleanroom/nemotron.env
  [[ -r $secret ]] || { echo "cleanroom-vm: --live needs $secret" >&2; exit 1; }
  append+=" cleanroom.live=1"
  extra+=(-fw_cfg "name=opt/cleanroom/nemotron.env,file=$secret")
fi

exec @qemu@/bin/qemu-system-x86_64 \
  -name cleanroom-vm \
  -enable-kvm -cpu host -smp 4 -m "$mem" \
  -nographic -serial mon:stdio \
  -kernel @kernel@ -initrd @initrd@ -append "$append" \
  -virtfs local,path=/nix/store,mount_tag=nixstore,security_model=none,readonly=on \
  -nic user,model=virtio-net-pci \
  "${extra[@]}"
