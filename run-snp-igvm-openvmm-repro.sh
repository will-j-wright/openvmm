#!/bin/bash
# Run the SNP IGVM OpenVMM repro over SSH and automatically quit OpenVMM when a
# known failure pattern or timeout is observed.

set -euo pipefail

HOST="${SNP_IGVM_REPRO_HOST:-${SNP_REPRO_HOST:-kvm-snp}}"
REMOTE_SCRIPT="${SNP_IGVM_REPRO_REMOTE_SCRIPT:-~/snp-openvmm/run-snp-igvm-openvmm.sh}"
TIMEOUT_SECONDS="${SNP_IGVM_REPRO_TIMEOUT_SECONDS:-${SNP_REPRO_TIMEOUT_SECONDS:-180}}"
ERROR_PATTERN="${SNP_IGVM_REPRO_ERROR_PATTERN:-${SNP_REPRO_ERROR_PATTERN:-fatal error|failed to run VP|Bad address|guest halted|triple fault|panicked at|assertion failed|abnormal exit|SIGABRT|core dumped|node failure|Connection reset by peer}}"
SUCCESS_PATTERN="${SNP_IGVM_REPRO_SUCCESS_PATTERN:-${SNP_REPRO_SUCCESS_PATTERN:-Run /init as init process|Dropping to a shell|~ #}}"

python3 - "$HOST" "$REMOTE_SCRIPT" "$TIMEOUT_SECONDS" "$ERROR_PATTERN" "$SUCCESS_PATTERN" <<'PY'
import os
import pty
import re
import select
import signal
import subprocess
import sys
import time

host, remote_script, timeout_seconds, error_pattern, success_pattern = sys.argv[1:]
timeout_seconds = int(timeout_seconds)
pattern = re.compile(error_pattern)
success = re.compile(success_pattern)

argv = ["ssh", "-t", host, remote_script]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)

deadline = time.monotonic() + timeout_seconds
buffer = ""
matched_error = False
matched_success = False
timed_out = False
child_status = None
pending_quit = False
pending_quit_since = None

def send_quit():
    os.write(fd, b"\x11q\r")

try:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            send_quit()
            break

        readable, _, _ = select.select([fd], [], [], min(1, remaining))
        if not readable:
            if pending_quit and pending_quit_since is not None and time.monotonic() - pending_quit_since > 2:
                send_quit()
                break
            continue

        try:
            data = os.read(fd, 4096)
        except OSError:
            finished, status = os.waitpid(pid, os.WNOHANG)
            if finished:
                child_status = status
            break
        if not data:
            finished, status = os.waitpid(pid, os.WNOHANG)
            if finished:
                child_status = status
            break

        text = data.decode(errors="replace")
        print(text, end="", flush=True)
        buffer = (buffer + text)[-8192:]
        if pattern.search(buffer):
            matched_error = True
            if not pending_quit:
                pending_quit = True
                pending_quit_since = time.monotonic()
        if success.search(buffer):
            matched_success = True
            if not pending_quit:
                pending_quit = True
                pending_quit_since = time.monotonic()
        if pending_quit and "openvmm>" in buffer:
            send_quit()
            break
        if pending_quit and pending_quit_since is not None and time.monotonic() - pending_quit_since > 2:
            send_quit()
            break

    # Give OpenVMM a moment to process the quit sequence before escalating.
    end = time.monotonic() + 10
    while time.monotonic() < end:
        readable, _, _ = select.select([fd], [], [], 0.5)
        if readable:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            print(data.decode(errors="replace"), end="", flush=True)
        finished, status = os.waitpid(pid, os.WNOHANG)
        if finished:
            child_status = status
            break

    if child_status is not None:
        child_exit = os.waitstatus_to_exitcode(child_status)
        if matched_error:
            sys.exit(1)
        if matched_success:
            sys.exit(0)
        if timed_out:
            sys.exit(124)
        if child_exit != 0:
            print(f"\nSNP IGVM repro command exited unexpectedly with status {child_exit}", file=sys.stderr)
        sys.exit(child_exit)

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    finished, status = os.waitpid(pid, 0)
    if matched_error:
        sys.exit(1)
    if matched_success:
        sys.exit(0)
    if timed_out:
        sys.exit(124)
    sys.exit(os.waitstatus_to_exitcode(status))
except KeyboardInterrupt:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    raise
PY
