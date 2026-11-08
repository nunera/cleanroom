#!@shell@
# Stage 2: runs from the shared /nix/store on the tmpfs root. Sets up the filesystems, /etc, the
# network and the services' environment (replay or live LLM mode), then execs the init chosen on
# the kernel command line (cleanroom.init=dinit|s6-rc) as PID 1.
export PATH=@path@

cmdline_init=dinit
live=0
term=xterm-256color
for arg in $(cat /proc/cmdline); do
  case $arg in
    cleanroom.init=*) cmdline_init=${arg#cleanroom.init=} ;;
    cleanroom.live=1) live=1 ;;
    cleanroom.term=*) term=${arg#cleanroom.term=} ;;
  esac
done

# Filesystems. / is a tmpfs built by stage 1; /proc, /sys, /dev were moved here from it.
mkdir -p /dev/pts /dev/shm /run /tmp /var /etc /root /bin /usr/bin
mount -t devpts -o mode=0620,ptmxmode=0666 devpts /dev/pts
mount -t tmpfs -o mode=1777 shm /dev/shm
mount -t tmpfs -o mode=0755 run /run
mount -t tmpfs -o mode=1777 tmp /tmp
mount -t tmpfs -o mode=0755 var /var
ln -sfn /proc/self/fd /dev/fd
ln -sfn /proc/self/fd/0 /dev/stdin
ln -sfn /proc/self/fd/1 /dev/stdout
ln -sfn /proc/self/fd/2 /dev/stderr
ln -sfn @busybox@/bin/sh /bin/sh
ln -sfn @coreutils@/bin/env /usr/bin/env
mkdir -p /var/log /var/lib/cleanroom/keys /root/.config/cleanroom

# /etc
cat >/etc/passwd <<'EOF'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/var/empty:/bin/false
EOF
cat >/etc/group <<'EOF'
root:x:0:
tty:x:5:
nogroup:x:65534:
EOF
cat >/etc/hosts <<'EOF'
127.0.0.1 localhost cleanroom-vm
::1 localhost
EOF
echo "nameserver 10.0.2.3" >/etc/resolv.conf
echo cleanroom-vm >/etc/hostname
hostname cleanroom-vm
mkdir -p /etc/ssl/certs
ln -sfn @cacert@/etc/ssl/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt

# Network: QEMU user-mode networking, static.
ip link set lo up
ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0
ip route add default via 10.0.2.2

# Environment inherited by the init and every service.
export HOME=/root
export XDG_RUNTIME_DIR=/run
export XDG_STATE_HOME=/var/lib
export XDG_CONFIG_HOME=/root/.config
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export TERM=$term
export COLORTERM=truecolor
export LANG=C.UTF-8
cd /root

if [ $live = 1 ]; then
  mode=live
  secret=/sys/firmware/qemu_fw_cfg/by_name/opt/cleanroom/nemotron.env/raw
  if [ -r $secret ]; then
    (umask 077 && cp $secret /root/.config/cleanroom/nemotron.env)
  else
    echo "cleanroom: live mode but no opt/cleanroom/nemotron.env in fw_cfg" >&2
  fi
else
  mode=replay
  export CLEANROOM_LLM_CACHE=replay
  export CLEANROOM_LLM_CACHE_DIR=@recordings@/llm
fi

case $cmdline_init in
  dinit)
    echo "cleanroom: booting plans/vm.json with dinit ($mode mode)"
    exec dinit --system --quiet --services-dir @dinitServices@
    ;;
  s6-rc)
    echo "cleanroom: booting plans/vm.json with s6-rc ($mode mode)"
    mkdir -p /run/service
    # s6-rc-init needs a running s6-svscan on /run/service; wait for it, then bring up the plan.
    (
      until s6-svscanctl -z /run/service 2>/dev/null; do sleep 0.1; done
      s6-rc-init -c @s6rcCompiled@ -l /run/s6-rc /run/service &&
        s6-rc -l /run/s6-rc -u change default
    ) </dev/null &
    exec s6-svscan /run/service
    ;;
  *)
    echo "cleanroom: unknown cleanroom.init=$cmdline_init (want dinit or s6-rc); dropping to a shell" >&2
    exec sh
    ;;
esac
