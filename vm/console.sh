#!@shell@
# cleanroom-console COMMAND [ARGS...]: run COMMAND on the serial console /dev/ttyS0 as its
# stdin/stdout/stderr and controlling terminal, sized to the host terminal the runner passed on
# the kernel command line (cleanroom.rows=, cleanroom.cols=).
export PATH=@path@:$PATH
tty=/dev/ttyS0
rows=
cols=
for arg in $(cat /proc/cmdline); do
  case $arg in
    cleanroom.rows=*) rows=${arg#cleanroom.rows=} ;;
    cleanroom.cols=*) cols=${arg#cleanroom.cols=} ;;
  esac
done
if [ -n "$rows" ] && [ -n "$cols" ]; then
  stty -F $tty rows "$rows" cols "$cols"
fi
# -c makes the tty the controlling terminal of the new session; -w waits so the init supervises
# the command itself, not a parent that already exited.
exec setsid -w -c "$@" <$tty >$tty 2>&1
