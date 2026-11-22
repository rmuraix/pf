#!/usr/bin/env python3
"""Smoke test for the pf TUI, run in a pseudo terminal (Unix only).

Usage: tui-smoke.py <quit|sigint> -- <pf command...>

Starts pf on a pty, generates ICMP traffic on loopback, opens the Events
view, then stops pf with `q` or SIGINT and checks that it exits with status 0
and leaves the terminal as it found it (cooked mode, main screen, cursor
shown).
"""
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time

ENTER_ALT, LEAVE_ALT, SHOW_CURSOR = b"\x1b[?1049h", b"\x1b[?1049l", b"\x1b[?25h"


def main() -> int:
    mode, sep, *cmd = sys.argv[1:]
    if mode not in ("quit", "sigint") or sep != "--" or not cmd:
        print(__doc__)
        return 2

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))

    def own_tty():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    pf = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave,
                          preexec_fn=own_tty, close_fds=True)
    output = b""

    def pump(seconds: float, until: bytes = b"") -> None:
        nonlocal output
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not (until and until in output):
            if select.select([master], [], [], 0.05)[0]:
                try:
                    output += os.read(master, 65536)
                except OSError:
                    return

    def fail(message: str) -> int:
        pf.kill()
        print(f"FAIL: {message}\n--- output ---\n{output.decode(errors='replace')}")
        return 1

    pump(15, until=ENTER_ALT)
    if ENTER_ALT not in output:
        return fail(f"UI did not start (exit status {pf.poll()})")

    subprocess.run(["ping", "-c", "3", "-i", "0.2", "127.0.0.1"],
                   stdout=subprocess.DEVNULL, check=True)
    pump(1.0)
    os.write(master, b"\t")  # Flows -> Events
    pump(5, until=b"ICMP")
    if b"ICMP" not in output:
        return fail("no ICMP event shown in the Events view")

    if mode == "quit":
        os.write(master, b"q")
    else:
        pf.send_signal(signal.SIGINT)
    try:
        status = pf.wait(timeout=10)
    except subprocess.TimeoutExpired:
        return fail("pf did not exit")
    pump(0.5)

    flags = termios.tcgetattr(slave)[3]
    problems = []
    if status != 0:
        problems.append(f"exit status {status}")
    if LEAVE_ALT not in output:
        problems.append("alternate screen not left")
    if SHOW_CURSOR not in output:
        problems.append("cursor not shown")
    if not flags & termios.ICANON or not flags & termios.ECHO:
        problems.append("terminal left in raw mode")
    if problems:
        return fail(", ".join(problems))
    print(f"OK ({mode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
