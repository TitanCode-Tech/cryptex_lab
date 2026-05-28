"""
launcher.py
-----------
Cross-platform launcher for CRYPTEX LAB. Lets the app
behave like a regular installed application: the user clicks a shortcut,
Streamlit starts in the background, the default browser opens to the app,
and closing the launcher (Ctrl-C / closing its console window) shuts the
server down cleanly.

This script is intended to be invoked by the platform shortcut created by
install.py. You can also run it directly:

    python launcher.py            # default host localhost, port 8501
    python launcher.py --no-browser
    python launcher.py --port 9000

SECURITY NOTES
==============
* The launcher only uses `socket` to probe localhost readiness; it makes
  NO outbound network calls.
* Streamlit is started with `--server.address localhost` and
  `--browser.gatherUsageStats false` regardless of what the bundled
  config file says (defence-in-depth so the lab cannot accidentally bind
  to a public interface). `localhost` resolves to 127.0.0.1 / ::1 via
  the host's name-resolution; we never query DNS or anything remote.
* The launcher does not read, modify, or display any mnemonic / private
  data. It only manages the lifecycle of the Streamlit subprocess.
"""

from __future__ import annotations

import argparse
import atexit
import os
import signal
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path


# Bound to localhost only - never expose the lab to other interfaces.
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8501
# How long we wait for Streamlit to become ready before giving up.
READY_TIMEOUT_S = 30


def project_root() -> Path:
    """The directory this script lives in."""
    return Path(__file__).resolve().parent


def find_streamlit_executable(root: Path) -> list[str]:
    """
    Return the argv prefix that runs Streamlit. Prefers the project's own
    venv (created by install.py) but falls back to the current Python
    interpreter with `-m streamlit` for ad-hoc runs.
    """
    if sys.platform == "win32":
        candidate = root / "venv" / "Scripts" / "streamlit.exe"
    else:
        candidate = root / "venv" / "bin" / "streamlit"
    if candidate.exists():
        return [str(candidate)]
    return [sys.executable, "-m", "streamlit"]


def is_port_ready(host: str, port: int) -> bool:
    """
    Try a TCP connect to host:port. Localhost-only by construction.

    `localhost` can resolve to multiple addresses (IPv4 + IPv6) depending
    on the host's name resolution, but Streamlit only binds to one of
    them. We use getaddrinfo to enumerate candidates and accept the
    first that connects.
    """
    try:
        infos = socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        return False
    for family, _socktype, _proto, _canon, sockaddr in infos:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                s.connect(sockaddr)
                return True
        except OSError:
            continue
    return False


def wait_for_server(host: str, port: int, timeout: float) -> bool:
    """Poll the local port until Streamlit accepts a connection."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_port_ready(host, port):
            return True
        time.sleep(0.3)
    return False


def build_streamlit_argv(root: Path, host: str, port: int) -> list[str]:
    """Compose the full argv for the Streamlit subprocess."""
    app_file = root / "app.py"
    if not app_file.exists():
        raise SystemExit(f"app.py not found at {app_file}")
    argv = find_streamlit_executable(root) + [
        "run",
        str(app_file),
        # Defence-in-depth - explicit flags even though config.toml has them.
        "--server.address", host,
        "--server.port", str(port),
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false",
    ]
    return argv


def _stop(proc: subprocess.Popen) -> None:
    """Best-effort clean shutdown of the Streamlit subprocess."""
    if proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            # Send Ctrl-Break to the process group so Streamlit's signal
            # handler can run; CTRL_C_EVENT does not work for grandchildren.
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception:
        # Last resort - we want shutdown to always finish.
        try:
            proc.kill()
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Launch CRYPTEX LAB as a desktop app."
    )
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="Bind address (default: localhost). "
                             "Do not change unless you know what you are doing.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not auto-open the browser.")
    parser.add_argument("--timeout", type=float, default=READY_TIMEOUT_S,
                        help="Seconds to wait for Streamlit to become ready.")
    args = parser.parse_args(argv)

    if args.host not in ("localhost", "127.0.0.1", "::1"):
        # Hard refusal - this app is offline-only by design.
        print(
            f"[launcher] Refusing to bind to {args.host!r}: the lab is "
            "intended for localhost only. Pass --host localhost."
        )
        return 2

    # Force line-buffered stdout so progress lines appear live in the
    # console / shortcut window instead of after the subprocess finishes.
    try:
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass

    root = project_root()
    argv_full = build_streamlit_argv(root, args.host, args.port)

    # Spawn Streamlit. On Windows we put it in a new process group so we can
    # later send CTRL_BREAK without also killing this launcher.
    popen_kwargs: dict = {"cwd": str(root)}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    print(f"[launcher] starting Streamlit ({' '.join(argv_full[:2])} ...)")
    proc = subprocess.Popen(argv_full, **popen_kwargs)
    atexit.register(_stop, proc)

    # If the user closes the console window or hits Ctrl-C we want to shut
    # Streamlit down gracefully.
    def _handle_signal(_signum, _frame):
        _stop(proc)
        sys.exit(0)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle_signal)
        except (ValueError, OSError):
            pass  # Some signals are not available on every platform.

    print(f"[launcher] waiting for http://{args.host}:{args.port} ...")
    if not wait_for_server(args.host, args.port, args.timeout):
        _stop(proc)
        print(
            f"[launcher] Streamlit did not become ready within "
            f"{args.timeout:.0f}s. Is something already bound to port "
            f"{args.port}?"
        )
        return 1

    url = f"http://{args.host}:{args.port}"
    print(f"[launcher] ready. Opening {url} in your browser.")
    print("[launcher] Close this window to quit the app.")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception as e:
            print(f"[launcher] could not auto-open browser: {e}")
            print(f"[launcher] paste this URL into your browser instead: {url}")

    # Block until Streamlit exits (or the user interrupts us).
    try:
        return proc.wait()
    except KeyboardInterrupt:
        _stop(proc)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
