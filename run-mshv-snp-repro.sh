#!/usr/bin/env bash
# Build, deploy, and run the MSHV SNP direct-boot repro.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

HOST="${MSHV_SNP_HOST:-wedson-mshv}"
ACI_ROOT="${MSHV_SNP_ACI_ROOT:-$HOME/ai/leafeon/aci-6.6}"
OPENVMM_BIN="${MSHV_SNP_OPENVMM:-$REPO_ROOT/target/x86_64-unknown-linux-musl/debug/openvmm}"
KERNEL="${MSHV_SNP_KERNEL:-$ACI_ROOT/out/snp-nord/arch/x86/boot/bzImage}"
INITRD="${MSHV_SNP_INITRD:-$REPO_ROOT/.packages/underhill-deps-private/x64/initrd}"
MEMORY="${MSHV_SNP_MEMORY:-160MB}"
PROCESSORS="${MSHV_SNP_PROCESSORS:-1}"
TIMEOUT_SECONDS="${MSHV_SNP_TIMEOUT_SECONDS:-90}"
OPENVMM_LOG="${OPENVMM_LOG:-info,virt_mshv=debug}"
DEVICE_TEST="${MSHV_SNP_DEVICE_TEST:-none}"
CONSOLE="${MSHV_SNP_CONSOLE:-serial}"
RESTRICTED_INJECTION="${MSHV_SNP_RESTRICTED_INJECTION:-0}"
DISABLE_CPUID_OFFLOAD="${MSHV_SNP_DISABLE_CPUID_OFFLOAD:-0}"
case "$CONSOLE" in
    serial)
        DEFAULT_KERNEL_CMDLINE="console=ttyS0 earlyprintk=serial earlycon panic=-1 nokaslr maxcpus=$PROCESSORS"
        ;;
    virtio)
        DEFAULT_KERNEL_CMDLINE="console=hvc0 panic=-1 nokaslr maxcpus=$PROCESSORS"
        ;;
    *)
        echo "ERROR: MSHV_SNP_CONSOLE must be serial or virtio" >&2
        exit 2
        ;;
esac
if [[ "$DEVICE_TEST" != none ]]; then
    DEFAULT_KERNEL_CMDLINE+=" ovmm_device_test=$DEVICE_TEST"
fi
KERNEL_CMDLINE="${MSHV_SNP_CMDLINE:-$DEFAULT_KERNEL_CMDLINE}"
BUILD_OPENVMM="${MSHV_SNP_BUILD_OPENVMM:-1}"
BUILD_KERNEL="${MSHV_SNP_BUILD_KERNEL:-0}"
KEEP_REMOTE="${MSHV_SNP_KEEP_REMOTE:-0}"
SSH_OPTS=(
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o ServerAliveInterval=5
    -o ServerAliveCountMax=3
)

usage() {
    cat <<EOF
Usage: $(basename "$0")

Build, deploy, and run the MSHV SNP direct-boot repro on
wedson-mshv. Configuration is provided through environment variables:

  MSHV_SNP_HOST              SSH host (default: wedson-mshv)
  MSHV_SNP_ACI_ROOT          ACI Linux checkout
  MSHV_SNP_OPENVMM           static-musl OpenVMM binary
  MSHV_SNP_KERNEL            ACI bzImage
  MSHV_SNP_INITRD            direct-boot initrd
  MSHV_SNP_BUILD_OPENVMM     build OpenVMM first (default: 1)
  MSHV_SNP_BUILD_KERNEL      incrementally build the ACI kernel (default: 0)
  MSHV_SNP_MEMORY            guest memory (default: 160MB)
  MSHV_SNP_PROCESSORS        guest processor count (default: 1)
  MSHV_SNP_TIMEOUT_SECONDS   boot timeout (default: 90)
  MSHV_SNP_DEVICE_TEST       device scenario: none | blk | net | both (default: none)
  MSHV_SNP_CONSOLE           console device: serial | virtio (default: serial)
  MSHV_SNP_RESTRICTED_INJECTION
                              enable SNP restricted interrupt injection (default: 0)
  MSHV_SNP_DISABLE_CPUID_OFFLOAD
                              forward SNP GHCB CPUID requests to OpenVMM (default: 0)
  MSHV_SNP_KEEP_REMOTE       retain a successful remote run (default: 0)
EOF
}

if (( $# != 0 )); then
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        usage
        exit 0
    fi
    usage >&2
    exit 2
fi

if [[ ! "$PROCESSORS" =~ ^[1-9][0-9]{0,2}$ ]] || (( PROCESSORS > 255 )); then
    echo "ERROR: MSHV_SNP_PROCESSORS must be an integer from 1 through 255" >&2
    exit 2
fi
if [[ ! "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]{0,4}$ ]]; then
    echo "ERROR: MSHV_SNP_TIMEOUT_SECONDS must be an integer from 1 through 99999" >&2
    exit 2
fi
if [[ ! "$DEVICE_TEST" =~ ^(none|blk|net|both)$ ]]; then
    echo "ERROR: MSHV_SNP_DEVICE_TEST must be none, blk, net, or both" >&2
    exit 2
fi

for value in "$BUILD_OPENVMM" "$BUILD_KERNEL" "$KEEP_REMOTE" "$RESTRICTED_INJECTION" "$DISABLE_CPUID_OFFLOAD"; do
    if [[ "$value" != 0 && "$value" != 1 ]]; then
        echo "ERROR: boolean configuration values must be 0 or 1" >&2
        exit 2
    fi
done

for command in cargo python3 scp sha256sum ssh; do
    if ! command -v "$command" >/dev/null; then
        echo "ERROR: required command is unavailable: $command" >&2
        exit 2
    fi
done

change_id="unknown"
if [[ -d "$REPO_ROOT/.jj" ]] && command -v jj >/dev/null; then
    change_id="$(cd "$REPO_ROOT" && jj log --no-graph -r @ -T 'change_id' 2>/dev/null || true)"
    change_id="${change_id:0:8}"
    [[ -n "$change_id" ]] || change_id="unknown"
fi

printf -v run_nonce '%08x' "$(((RANDOM << 16) ^ RANDOM ^ $$))"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$change_id-$run_nonce"
logs_dir="$REPO_ROOT/target/mshv-snp/$run_id"
if (( PROCESSORS == 1 )); then
    console_log="$logs_dir/bsp.console.log"
else
    console_log="$logs_dir/smp.console.log"
fi
deploy_log="$logs_dir/deploy.log"
manifest="$logs_dir/manifest.txt"
mkdir -p "$logs_dir"

remote_dir=
remote_staged=0
run_succeeded=0
generated_initrd_dir=

quote_command() {
    local quoted
    printf -v quoted '%q ' "$@"
    printf '%s' "${quoted% }"
}

cleanup_remote_process() {
    [[ "$remote_staged" == 1 ]] || return 0

    local quoted_dir cleanup_command
    printf -v quoted_dir '%q' "$remote_dir"
    cleanup_command="cd $quoted_dir && if test -f openvmm.pgid; then
        pgid=\$(cat openvmm.pgid)
        case \"\$pgid\" in
            ''|*[!0-9]*) exit 2 ;;
        esac
        if sudo -n /usr/bin/kill -0 -- \"-\$pgid\" 2>/dev/null; then
            process_cwd=\$(sudo -n /usr/bin/readlink \"/proc/\$pgid/cwd\" 2>/dev/null || true)
            if test -n \"\$process_cwd\" && test \"\$process_cwd\" != $quoted_dir; then
                echo \"refusing to signal process group \$pgid with cwd \$process_cwd\" >&2
                exit 3
            fi
            if test -z \"\$process_cwd\" &&
                ! sudo -n /usr/bin/kill -0 -- \"-\$pgid\" 2>/dev/null; then
                exit 0
            fi
            sudo -n /usr/bin/kill -TERM -- \"-\$pgid\"
            i=0
            while sudo -n /usr/bin/kill -0 -- \"-\$pgid\" 2>/dev/null && test \"\$i\" -lt 20; do
                sleep 0.25
                i=\$((i + 1))
            done
            if sudo -n /usr/bin/kill -0 -- \"-\$pgid\" 2>/dev/null; then
                sudo -n /usr/bin/kill -KILL -- \"-\$pgid\"
            fi
        fi
    fi"
    ssh "${SSH_OPTS[@]}" "$HOST" "$cleanup_command"
}

on_exit() {
    local status=$?
    trap - EXIT INT TERM

    if [[ -n "$generated_initrd_dir" ]]; then
        rm -rf -- "$generated_initrd_dir"
    fi

    if ! cleanup_remote_process; then
        echo "ERROR: failed to clean the recorded remote OpenVMM process group" >&2
        (( status != 0 )) || status=1
    fi

    if [[ "$remote_staged" == 1 && "$run_succeeded" == 1 && "$KEEP_REMOTE" == 0 ]]; then
        local quoted_dir
        printf -v quoted_dir '%q' "$remote_dir"
        if ! ssh "${SSH_OPTS[@]}" "$HOST" "rm -rf -- $quoted_dir"; then
            echo "ERROR: failed to remove successful remote run directory: $remote_dir" >&2
            (( status != 0 )) || status=1
        fi
    elif [[ "$remote_staged" == 1 ]]; then
        echo "Remote run retained at $HOST:$remote_dir" >&2
    fi

    exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Checking $HOST..." | tee -a "$deploy_log"
remote_home="$(
    ssh "${SSH_OPTS[@]}" "$HOST" \
        'set -eu; sudo -n true; test -x /usr/bin/kill; test -x /usr/bin/readlink; command -v timeout >/dev/null; command -v setsid >/dev/null; setsid --help 2>&1 | grep -q -- --wait; printf %s "$HOME"' \
        | tee -a "$deploy_log"
)"
if [[ -z "$remote_home" || "$remote_home" != /* ]]; then
    echo "ERROR: failed to resolve the remote home directory" >&2
    exit 3
fi
remote_dir="$remote_home/mshv-snp-openvmm/runs/$run_id"
remote_base="$remote_home/mshv-snp-openvmm/runs"

if [[ "$BUILD_KERNEL" == 1 ]]; then
    if [[ ! -x "$ACI_ROOT/build-snp-guest.sh" ]]; then
        echo "ERROR: missing ACI kernel build helper: $ACI_ROOT/build-snp-guest.sh" >&2
        exit 3
    fi
    echo "Building the ACI SNP guest kernel..." | tee -a "$deploy_log"
    (
        cd "$ACI_ROOT"
        SNP_GUEST_OUT="$ACI_ROOT/out/snp-nord" \
            SNP_GUEST_BASE_CONFIG="$ACI_ROOT/arch/x86/configs/nord_defconfig" \
            ./build-snp-guest.sh build
    ) 2>&1 | tee -a "$deploy_log"
fi

if [[ "$BUILD_OPENVMM" == 1 ]]; then
    if [[ ! -f "$INITRD" ]]; then
        echo "Restoring packaged build dependencies..." | tee -a "$deploy_log"
        (cd "$REPO_ROOT" && cargo xflowey restore-packages) 2>&1 | tee -a "$deploy_log"
    fi
    echo "Building static-musl OpenVMM..." | tee -a "$deploy_log"
    (cd "$REPO_ROOT" && cargo build --target x86_64-unknown-linux-musl -p openvmm) \
        2>&1 | tee -a "$deploy_log"
fi

check_artifact() {
    local name=$1
    local path=$2
    local executable=${3:-0}

    if [[ ! -f "$path" || ! -s "$path" || ! -r "$path" ]]; then
        echo "ERROR: missing, empty, or unreadable $name: $path" >&2
        exit 3
    fi
    if [[ "$executable" == 1 && ! -x "$path" ]]; then
        echo "ERROR: $name is not executable: $path" >&2
        exit 3
    fi
}

check_artifact "OpenVMM binary" "$OPENVMM_BIN" 1
check_artifact "ACI kernel" "$KERNEL"
check_artifact "initrd" "$INITRD"

if [[ "$CONSOLE" == virtio ]]; then
    generated_initrd_dir="$(mktemp -d)"
    mkdir "$generated_initrd_dir/root"
    (
        cd "$generated_initrd_dir/root"
        gzip -dc "$INITRD" | cpio -id --quiet
        mv init init.base
        printf '%s\n' \
            '#!/bin/sh' \
            "dmesg | grep 'smp: Brought up' || true" \
            'exec /init.base "$@"' >init
        chmod 755 init
        find . -print0 | cpio --null -o --quiet -H newc |
            gzip -n >"$generated_initrd_dir/initrd"
    )
    INITRD="$generated_initrd_dir/initrd"
fi

openvmm_hash="$(sha256sum "$OPENVMM_BIN" | awk '{print $1}')"
kernel_hash="$(sha256sum "$KERNEL" | awk '{print $1}')"
initrd_hash="$(sha256sum "$INITRD" | awk '{print $1}')"
artifact_bytes="$(
    stat -c %s "$OPENVMM_BIN"
    stat -c %s "$KERNEL"
    stat -c %s "$INITRD"
)"
required_kib=0
while IFS= read -r bytes; do
    required_kib=$((required_kib + (bytes + 1023) / 1024))
done <<<"$artifact_bytes"
required_kib=$((required_kib + 64 * 1024))

remote_available_kib="$(
    ssh "${SSH_OPTS[@]}" "$HOST" "df -Pk $(printf '%q' "$remote_home")" |
        awk 'NR == 2 { print $4 }'
)"
if [[ ! "$remote_available_kib" =~ ^[0-9]+$ ]] || (( remote_available_kib < required_kib )); then
    echo "ERROR: insufficient remote disk space: need ${required_kib} KiB, have ${remote_available_kib:-unknown} KiB" >&2
    echo "       remove obsolete retained runs under $HOST:$remote_base" >&2
    exit 3
fi

remote_kernel="$(
    ssh "${SSH_OPTS[@]}" "$HOST" \
        'printf "uname=%s\nmshv=%s\n" "$(uname -sr)" "$(ls -l /dev/mshv 2>&1)"'
)"

{
    printf 'run_id=%s\n' "$run_id"
    printf 'change_id=%s\n' "$change_id"
    printf 'host=%s\n' "$HOST"
    printf 'remote_dir=%s\n' "$remote_dir"
    printf 'openvmm=%s\nopenvmm_sha256=%s\n' "$OPENVMM_BIN" "$openvmm_hash"
    printf 'kernel=%s\nkernel_sha256=%s\n' "$KERNEL" "$kernel_hash"
    printf 'initrd=%s\ninitrd_sha256=%s\n' "$INITRD" "$initrd_hash"
    printf 'memory=%s\nprocessors=%s\ntimeout_seconds=%s\n' "$MEMORY" "$PROCESSORS" "$TIMEOUT_SECONDS"
    printf 'restricted_injection=%s\n' "$RESTRICTED_INJECTION"
    printf 'disable_cpuid_offload=%s\n' "$DISABLE_CPUID_OFFLOAD"
    printf 'openvmm_log=%s\nkernel_cmdline=%s\n' "$OPENVMM_LOG" "$KERNEL_CMDLINE"
    printf '%s\n' "$remote_kernel"
} >"$manifest"

echo "Staging artifacts in $HOST:$remote_dir..." | tee -a "$deploy_log"
quoted_remote_dir="$(printf '%q' "$remote_dir")"
quoted_remote_base="$(printf '%q' "$remote_base")"
ssh "${SSH_OPTS[@]}" "$HOST" \
    "mkdir -p -- $quoted_remote_base && mkdir -- $quoted_remote_dir" \
    2>&1 | tee -a "$deploy_log"
remote_staged=1

scp -q "${SSH_OPTS[@]}" "$OPENVMM_BIN" "$HOST:$remote_dir/openvmm.new"
scp -q "${SSH_OPTS[@]}" "$KERNEL" "$HOST:$remote_dir/bzImage.new"
scp -q "${SSH_OPTS[@]}" "$INITRD" "$HOST:$remote_dir/initrd.new"

verify_command="cd $quoted_remote_dir &&
    test \"\$(sha256sum openvmm.new | awk '{print \$1}')\" = $(printf '%q' "$openvmm_hash") &&
    test \"\$(sha256sum bzImage.new | awk '{print \$1}')\" = $(printf '%q' "$kernel_hash") &&
    test \"\$(sha256sum initrd.new | awk '{print \$1}')\" = $(printf '%q' "$initrd_hash") &&
    mv openvmm.new openvmm &&
    mv bzImage.new bzImage &&
    mv initrd.new initrd &&
    chmod 755 openvmm"
ssh "${SSH_OPTS[@]}" "$HOST" "$verify_command" 2>&1 | tee -a "$deploy_log"

openvmm_command=(
    env "OPENVMM_LOG=$OPENVMM_LOG"
    timeout --foreground "$TIMEOUT_SECONDS"
    ./openvmm
    --hypervisor mshv
    --isolation snp
    --hv
    --no-vmbus
    --kernel ./bzImage
    --initrd ./initrd
    -m "$MEMORY"
    -p "$PROCESSORS"
    -c "$KERNEL_CMDLINE"
)
case "$CONSOLE" in
    serial)
        openvmm_command+=(--com1 console)
        ;;
    virtio)
        # Keep ACI Linux IOAPIC support enabled for this configuration.
        # The guest boots and transmits console output with IOAPIC disabled,
        # but host-to-guest input does not complete. The current virtio-console
        # path therefore relies on PCI INTx fallback through the emulated
        # IOAPIC rather than a working MSI-X receive interrupt.
        openvmm_command+=(--com1 none)
        if [[ "$DEVICE_TEST" == none ]]; then
            openvmm_command+=(
                --pcie-root-complex console-rc
                --pcie-root-port console-rc:console
            )
        else
            openvmm_command+=(--pcie-root-port rc0:console)
        fi
        openvmm_command+=(
            --virtio-console console
            --virtio-console-pcie-port console
        )
        ;;
esac
if [[ "$RESTRICTED_INJECTION" == 1 ]]; then
    openvmm_command+=(--snp-restricted-injection)
fi
if [[ "$DISABLE_CPUID_OFFLOAD" == 1 ]]; then
    openvmm_command+=(--snp-disable-cpuid-offload)
fi
case "$DEVICE_TEST" in
    none)
        ;;
    blk)
        openvmm_command+=(
            --pcie-root-complex rc0
            --pcie-root-port rc0:blk
            --virtio-blk mem:16M,pcie_port=blk
        )
        ;;
    net)
        openvmm_command+=(
            --pcie-root-complex rc0
            --pcie-root-port rc0:net
            --virtio-net pcie_port=net:consomme
        )
        ;;
    both)
        openvmm_command+=(
            --pcie-root-complex rc0
            --pcie-root-port rc0:blk
            --pcie-root-port rc0:net
            --virtio-blk mem:16M,pcie_port=blk
            --virtio-net pcie_port=net:consomme
        )
        ;;
esac
quoted_openvmm_command="$(quote_command "${openvmm_command[@]}")"
runner_body="echo \$\$ > openvmm.pgid; exec $quoted_openvmm_command"
remote_command="cd $quoted_remote_dir && exec sudo -n setsid --wait sh -c $(printf '%q' "$runner_body")"

{
    printf '\ncommand='
    printf '%q ' "${openvmm_command[@]}"
    printf '\n'
} >>"$manifest"

echo "Running $PROCESSORS-vCPU MSHV SNP repro; full console: $console_log"
set +e
python3 - "$HOST" "$remote_command" "$TIMEOUT_SECONDS" "$PROCESSORS" "$DEVICE_TEST" "$CONSOLE" "$console_log" <<'PY'
import os
import pty
import re
import select
import signal
import sys
import termios
import time

host, remote_command, timeout_text, processors_text, device_test, console, log_path = sys.argv[1:]
timeout_seconds = int(timeout_text)
processors = int(processors_text)
device_marker = {
    "none": None,
    "blk": "OVMM_VIRTIO_BLK_OK",
    "net": "OVMM_VIRTIO_NET_OK",
    "both": "OVMM_VIRTIO_BOTH_OK",
}[device_test]
if console == "virtio":
    shell_ready = re.compile(
        r"can't access tty; job control turned off|"
        r"(?:^|[\r\n])~ #\s*$"
    )
else:
    shell_ready = re.compile(
        r"No root device specified\. Dropping to a shell\.|"
        r"can't access tty; job control turned off|"
        r"(?:^|[\r\n])~ #\s*$"
    )
fatal = re.compile(
    r"fatal error|failed to run VP|guest halted|triple fault|panicked at|"
    r"assertion failed|abnormal exit|SIGABRT|core dumped|Kernel panic"
)
smp_ready = re.compile(
    rf"smp: Brought up [0-9]+ node(?:s)?, {processors} CPU(?:s)?"
)

argv = [
    "ssh",
    "-tt",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=3",
    host,
    remote_command,
]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)

attrs = termios.tcgetattr(fd)
attrs[0] &= ~(termios.IXON | termios.IXOFF | termios.IXANY)
termios.tcsetattr(fd, termios.TCSANOW, attrs)

deadline = time.monotonic() + timeout_seconds + 15
buffer = ""
reached_shell = False
# The SMP bring-up marker is printed before a virtio console can be probed.
reached_processor_count = False
reached_device = device_marker is None
matched_fatal = False
fatal_since = None
missing_processors = False
device_probe_requested = False
input_probe_requested = False
input_probe_verified = console != "virtio"
control_prompt_requested = False
quit_sent = False
child_status = None
child_exit_deadline = None
timed_out = False

with open(log_path, "wb", buffering=0) as log:
    try:
        while True:
            now = time.monotonic()
            if child_status is None:
                finished, status = os.waitpid(pid, os.WNOHANG)
                if finished:
                    child_status = status
                    child_exit_deadline = now + 2

            if fatal_since is not None and now - fatal_since >= 2:
                break
            if child_exit_deadline is not None and now >= child_exit_deadline:
                break

            remaining = deadline - now
            if remaining <= 0:
                timed_out = True
                break

            wait = min(0.5, remaining)
            if fatal_since is not None:
                wait = min(wait, fatal_since + 2 - now)
            if child_exit_deadline is not None:
                wait = min(wait, child_exit_deadline - now)

            readable, _, _ = select.select([fd], [], [], max(0, wait))
            if not readable:
                continue

            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break

            os.write(sys.stdout.fileno(), data)
            log.write(data)
            text = data.decode(errors="replace")
            buffer = (buffer + text)[-16384:]

            if fatal.search(buffer):
                matched_fatal = True
                if fatal_since is None:
                    fatal_since = time.monotonic()
                continue

            if matched_fatal:
                continue

            if smp_ready.search(buffer):
                reached_processor_count = True
            if device_marker is not None and device_marker in buffer:
                reached_device = True
                if reached_shell and not input_probe_verified and not input_probe_requested:
                    print(
                        "\nMSHV SNP repro: testing virtio-console input",
                        file=sys.stderr,
                        flush=True,
                    )
                    os.write(
                        fd,
                        b"printf '%s%s\\n' OVMM_VIRTIO_CONSOLE_ INPUT_OK\n",
                    )
                    input_probe_requested = True
                    buffer = ""
                    continue

            if input_probe_requested and "OVMM_VIRTIO_CONSOLE_INPUT_OK" in buffer:
                input_probe_verified = True
                print(
                    "\nMSHV SNP repro: virtio-console input verified; quitting OpenVMM",
                    file=sys.stderr,
                    flush=True,
                )
                os.write(fd, b"\x11")
                control_prompt_requested = True
                input_probe_requested = False
                buffer = ""
                continue

            if not reached_shell and shell_ready.search(buffer):
                reached_shell = True
                if not reached_processor_count:
                    missing_processors = True
                    break
                if not reached_device:
                    probe = {
                        "blk": (
                            "test -b /dev/vda && "
                            "dd if=/dev/zero of=/dev/vda bs=512 count=1 conv=fsync && "
                            "echo OVMM_VIRTIO_BLK_OK"
                        ),
                        "net": (
                            "ip link set eth0 up && "
                            "ip addr add 10.0.0.2/24 dev eth0 && "
                            "ip route add default via 10.0.0.1 && "
                            "ping -c 1 -W 5 10.0.0.1 && "
                            "echo OVMM_VIRTIO_NET_OK"
                        ),
                        "both": (
                            "test -b /dev/vda && "
                            "dd if=/dev/zero of=/dev/vda bs=512 count=1 conv=fsync && "
                            "ip link set eth0 up && "
                            "ip addr add 10.0.0.2/24 dev eth0 && "
                            "ip route add default via 10.0.0.1 && "
                            "ping -c 1 -W 5 10.0.0.1 && "
                            "echo OVMM_VIRTIO_BOTH_OK"
                        ),
                    }[device_test]
                    print(
                        f"\nMSHV SNP repro: testing virtio-{device_test}",
                        file=sys.stderr,
                        flush=True,
                    )
                    os.write(fd, probe.encode() + b"\n")
                    device_probe_requested = True
                    buffer = ""
                    continue
                if not input_probe_verified:
                    print(
                        "\nMSHV SNP repro: testing virtio-console input",
                        file=sys.stderr,
                        flush=True,
                    )
                    os.write(
                        fd,
                        b"printf '%s%s\\n' OVMM_VIRTIO_CONSOLE_ INPUT_OK\n",
                    )
                    input_probe_requested = True
                    buffer = ""
                    continue
                print(
                    "\nMSHV SNP repro: initrd shell reached; quitting OpenVMM",
                    file=sys.stderr,
                    flush=True,
                )
                os.write(fd, b"\x11")
                control_prompt_requested = True
                buffer = ""
                continue

            if control_prompt_requested and not quit_sent and "openvmm>" in buffer:
                os.write(fd, b"q\r")
                quit_sent = True
                buffer = ""

        if child_status is None:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            terminate_deadline = time.monotonic() + 5
            terminate_child_exit_deadline = None
            pty_eof = False
            while time.monotonic() < terminate_deadline:
                now = time.monotonic()
                if not pty_eof:
                    readable, _, _ = select.select([fd], [], [], 0.1)
                else:
                    readable = []
                    time.sleep(0.1)
                if readable:
                    try:
                        data = os.read(fd, 4096)
                    except OSError:
                        data = b""
                    if data:
                        os.write(sys.stdout.fileno(), data)
                        log.write(data)
                        text = data.decode(errors="replace")
                        buffer = (buffer + text)[-16384:]
                        if fatal.search(buffer):
                            matched_fatal = True
                        if smp_ready.search(buffer):
                            reached_processor_count = True
                    else:
                        pty_eof = True

                if child_status is None:
                    finished, status = os.waitpid(pid, os.WNOHANG)
                    if finished:
                        child_status = status
                        terminate_child_exit_deadline = now + 2

                if child_status is not None and (
                    pty_eof
                    or (
                        terminate_child_exit_deadline is not None
                        and now >= terminate_child_exit_deadline
                    )
                ):
                    break

            if child_status is None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, child_status = os.waitpid(pid, 0)
    except KeyboardInterrupt:
        if child_status is None:
            try:
                finished, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                finished = pid
            if not finished:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                interrupt_deadline = time.monotonic() + 5
                while time.monotonic() < interrupt_deadline:
                    finished, _ = os.waitpid(pid, os.WNOHANG)
                    if finished:
                        break
                    time.sleep(0.1)
                else:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.waitpid(pid, 0)
        raise

if missing_processors:
    print(f"\nMSHV SNP repro failed: guest did not bring up {processors} CPUs", file=sys.stderr)
    sys.exit(1)
if not reached_device:
    print(f"\nMSHV SNP repro failed: {device_test} smoke marker was not observed", file=sys.stderr)
    sys.exit(1)
if matched_fatal:
    print("\nMSHV SNP repro failed: matched a fatal guest or OpenVMM error", file=sys.stderr)
    sys.exit(1)
if timed_out:
    print("\nMSHV SNP repro failed: timed out before reaching the initrd shell", file=sys.stderr)
    sys.exit(124)
if child_status is not None:
    exit_code = os.waitstatus_to_exitcode(child_status)
    if exit_code != 0:
        if exit_code < 0:
            exit_code = 128 - exit_code
        print(f"\nMSHV SNP repro failed: SSH exited with status {exit_code}", file=sys.stderr)
        sys.exit(exit_code)
if not reached_shell:
    print("\nMSHV SNP repro failed: SSH or OpenVMM exited before reaching the initrd shell", file=sys.stderr)
    sys.exit(1)
if not quit_sent:
    print("\nMSHV SNP repro failed: OpenVMM did not present its control prompt", file=sys.stderr)
    sys.exit(1)
if child_status is None:
    print("\nMSHV SNP repro failed: SSH did not exit", file=sys.stderr)
    sys.exit(1)
PY
run_status=$?
set -e

if (( run_status != 0 )); then
    echo "MSHV SNP repro failed with status $run_status; see $console_log" >&2
    exit "$run_status"
fi

run_succeeded=1
echo "MSHV SNP repro passed: the ACI guest reached its initrd shell with $PROCESSORS processor(s)"
echo "Logs: $logs_dir"
