"""
install.py
----------
Cross-platform installer for CRYPTEX LAB.

What it does (in this order):

  1. Verifies Python >= 3.10.
  2. Creates a virtualenv at ./venv if one is not already present.
  3. Installs the pinned dependencies from requirements.txt
     (skip with --skip-deps if you are reinstalling on an offline machine
      that already has a populated venv).
  4. Creates a platform-appropriate desktop shortcut:
       * Linux   - ~/.local/share/applications/cryptex-lab.desktop
       * macOS   - ~/Applications/CRYPTEX LAB.app/
       * Windows - %USERPROFILE%\\Desktop\\CRYPTEX LAB.lnk
                   AND a Start Menu entry under Programs/.
  5. Prints next steps.

Usage:
  python install.py                    # full install
  python install.py --skip-deps        # shortcuts only (post-sneakernet)
  python install.py --no-shortcut      # venv + deps only, no desktop entry

This script makes network calls ONLY during step 3 (pip). The runtime
launcher and the app itself remain fully offline.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import textwrap
import venv
from pathlib import Path


MIN_PYTHON = (3, 10)
APP_NAME = "CRYPTEX LAB"
APP_SLUG = "cryptex-lab"
APP_COMMENT = "CRYPTEX LAB - offline crypto wallet recovery & forensic workstation"
ROOT = Path(__file__).resolve().parent
ICON_PATH = ROOT / "assets" / "icon.png"


# ---------------------------------------------------------------------------
# Pretty output
# ---------------------------------------------------------------------------

def step(msg: str) -> None:
    print(f"\n==> {msg}")


def info(msg: str) -> None:
    print(f"    {msg}")


def warn(msg: str) -> None:
    print(f"!!  {msg}")


# ---------------------------------------------------------------------------
# Python / venv
# ---------------------------------------------------------------------------

def check_python() -> None:
    if sys.version_info < MIN_PYTHON:
        raise SystemExit(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required; you are "
            f"running {sys.version.split()[0]}."
        )


def venv_dir() -> Path:
    return ROOT / "venv"


def venv_python() -> Path:
    if sys.platform == "win32":
        return venv_dir() / "Scripts" / "python.exe"
    return venv_dir() / "bin" / "python"


def venv_launcher_executable() -> Path:
    """The python(w) the shortcut should run."""
    if sys.platform == "win32":
        # pythonw.exe runs without a console window, which is what you want
        # for a double-click experience. We fall back to python.exe if it is
        # missing.
        pyw = venv_dir() / "Scripts" / "pythonw.exe"
        if pyw.exists():
            return pyw
        return venv_dir() / "Scripts" / "python.exe"
    return venv_dir() / "bin" / "python"


def create_venv() -> None:
    if venv_dir().exists() and venv_python().exists():
        info("venv already present, skipping creation.")
        return
    step(f"Creating venv at {venv_dir()}")
    builder = venv.EnvBuilder(with_pip=True, clear=False, symlinks=(sys.platform != "win32"))
    builder.create(str(venv_dir()))


def install_requirements(offline: bool = False) -> None:
    req = ROOT / "requirements.txt"
    if not req.exists():
        raise SystemExit(f"requirements.txt not found at {req}")

    if offline:
        wheels_dir = ROOT / "offline_wheels"
        if not wheels_dir.exists() or not any(wheels_dir.iterdir()):
            raise SystemExit(
                f"offline_wheels/ not found or empty at {wheels_dir}.\n"
                "Run 'python download_wheels.py' on an internet-connected machine first,\n"
                "then copy the offline_wheels/ folder here."
            )
        step("Installing dependencies from offline_wheels/ (no internet required)")
        cmd = [str(venv_python()), "-m", "pip", "install", "--upgrade", "--no-index",
               "--find-links", str(wheels_dir), "pip"]
        subprocess.run(cmd)  # pip self-upgrade may not be in wheels; non-fatal
        cmd = [str(venv_python()), "-m", "pip", "install",
               "--no-index", "--find-links", str(wheels_dir),
               "-r", str(req)]
        subprocess.check_call(cmd)
    else:
        step("Installing dependencies (this is the only online step)")
        cmd = [str(venv_python()), "-m", "pip", "install", "--upgrade", "pip"]
        subprocess.check_call(cmd)
        cmd = [str(venv_python()), "-m", "pip", "install", "-r", str(req)]
        subprocess.check_call(cmd)


# ---------------------------------------------------------------------------
# Shortcut creation - platform-specific
# ---------------------------------------------------------------------------

def shortcut_target() -> tuple[Path, Path]:
    """(executable, script) the shortcut should run."""
    return venv_launcher_executable(), ROOT / "launcher.py"


# --- Linux .desktop ---------------------------------------------------------

def create_linux_shortcut() -> Path:
    apps_dir = Path.home() / ".local" / "share" / "applications"
    apps_dir.mkdir(parents=True, exist_ok=True)
    desktop_file = apps_dir / f"{APP_SLUG}.desktop"
    exe, script = shortcut_target()
    icon_line = f"Icon={ICON_PATH}\n        " if ICON_PATH.exists() else ""
    desktop_file.write_text(textwrap.dedent(f"""\
        [Desktop Entry]
        Type=Application
        Version=1.0
        Name={APP_NAME}
        Comment={APP_COMMENT}
        Exec={exe} {script}
        Path={ROOT}
        {icon_line}Terminal=true
        Categories=Utility;Security;Network;
        StartupNotify=true
        """))
    desktop_file.chmod(0o755)
    return desktop_file


# --- macOS .app bundle ------------------------------------------------------

def create_macos_app() -> Path:
    apps_dir = Path.home() / "Applications"
    apps_dir.mkdir(parents=True, exist_ok=True)
    app_bundle = apps_dir / f"{APP_NAME}.app"
    contents = app_bundle / "Contents"
    macos = contents / "MacOS"
    macos.mkdir(parents=True, exist_ok=True)

    exe, script = shortcut_target()
    # Tiny shell stub that launches the venv Python on launcher.py.
    runner = macos / "run"
    runner.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Launcher for {APP_NAME}.
        exec "{exe}" "{script}"
        """))
    runner.chmod(0o755)

    info_plist = contents / "Info.plist"
    info_plist.write_text(textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleName</key><string>{APP_NAME}</string>
            <key>CFBundleDisplayName</key><string>{APP_NAME}</string>
            <key>CFBundleIdentifier</key><string>local.{APP_SLUG}</string>
            <key>CFBundleExecutable</key><string>run</string>
            <key>CFBundleVersion</key><string>1.0</string>
            <key>CFBundleShortVersionString</key><string>1.0</string>
            <key>CFBundlePackageType</key><string>APPL</string>
            <key>LSMinimumSystemVersion</key><string>10.12</string>
            <key>LSUIElement</key><false/>
        </dict>
        </plist>
        """))
    return app_bundle


# --- Windows .lnk via PowerShell -------------------------------------------

def _ps_escape(s: str) -> str:
    """Escape a string for embedding in a PowerShell single-quoted string."""
    return s.replace("'", "''")


def _create_windows_lnk(lnk_path: Path) -> None:
    exe, script = shortcut_target()
    lnk_path.parent.mkdir(parents=True, exist_ok=True)
    ps = textwrap.dedent(f"""\
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut('{_ps_escape(str(lnk_path))}')
        $Shortcut.TargetPath = '{_ps_escape(str(exe))}'
        $Shortcut.Arguments = '"{_ps_escape(str(script))}"'
        $Shortcut.WorkingDirectory = '{_ps_escape(str(ROOT))}'
        $Shortcut.Description = '{_ps_escape(APP_COMMENT)}'
        $Shortcut.WindowStyle = 7
        $Shortcut.Save()
        """)
    subprocess.check_call(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps]
    )


def create_windows_shortcut() -> list[Path]:
    desktop = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Desktop"
    start_menu = (
        Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
        / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    )
    out: list[Path] = []
    for parent in (desktop, start_menu):
        lnk = parent / f"{APP_NAME}.lnk"
        try:
            _create_windows_lnk(lnk)
            out.append(lnk)
        except subprocess.CalledProcessError as e:
            warn(f"Could not create shortcut at {lnk}: {e}")
    return out


# --- Dispatcher -------------------------------------------------------------

def create_shortcuts() -> list[Path]:
    step("Creating desktop shortcut")
    if sys.platform.startswith("linux"):
        return [create_linux_shortcut()]
    if sys.platform == "darwin":
        return [create_macos_app()]
    if sys.platform == "win32":
        return create_windows_shortcut()
    warn(f"Unknown platform {sys.platform!r}; no shortcut created. "
         "You can still run `python launcher.py` manually.")
    return []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"Install {APP_NAME}.")
    parser.add_argument("--skip-deps", action="store_true",
                        help="Skip pip install (use when the venv is already populated).")
    parser.add_argument("--offline", action="store_true",
                        help="Install from offline_wheels/ instead of PyPI. "
                             "Requires running download_wheels.py first on an "
                             "internet-connected machine.")
    parser.add_argument("--no-shortcut", action="store_true",
                        help="Do not create a desktop shortcut.")
    args = parser.parse_args(argv)

    check_python()
    info(f"Project root: {ROOT}")

    create_venv()

    if args.skip_deps:
        info("--skip-deps: not running pip. Existing venv is assumed populated.")
    elif args.offline:
        install_requirements(offline=True)
    else:
        install_requirements(offline=False)

    created: list[Path] = []
    if not args.no_shortcut:
        created = create_shortcuts()

    step("Install complete")
    if created:
        info("Created:")
        for p in created:
            info(f"  - {p}")
    info(f"You can also start the app any time with: python launcher.py "
         f"(from {ROOT})")
    info(
        "Reminder: this is an offline tool. Disconnect from the internet "
        "BEFORE you paste a real mnemonic."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
