#!/usr/bin/env python3
"""
Mac Cleaner — Terminal cleaner similar to CleanMyMac's System Junk scan.
Scans common junk locations and lets you review/delete selectively.
Usage: python3 clean_mac.py
"""

import os
import sys
import shutil
import subprocess
import platform
import fnmatch
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# ── ANSI helpers ────────────────────────────────────────────────────────────
RST  = "\033[0m"
BOLD = "\033[1m"
DIM  = "\033[2m"
CYAN = "\033[36m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED   = "\033[31m"
MAGENTA = "\033[35m"
WHITE  = "\033[37m"
BG_MAGENTA = "\033[45m"
BG_GREEN   = "\033[42m"
BG_RED     = "\033[41m"

def fmt_size(b: int) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"

def clear(): os.system("clear")

def banner():
    print(f"{MAGENTA}{BOLD}")
    print("╔══════════════════════════════════════════════════════╗")
    print("║             🧹  M A C   C L E A N E R               ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(RST)

# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class JunkCategory:
    name: str
    description: str
    entries: List["JunkEntry"] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(e.size_bytes for e in self.entries if e.selected)

    @property
    def selected_count(self) -> int:
        return sum(1 for e in self.entries if e.selected)

@dataclass
class JunkEntry:
    path: Path
    label: str
    size_bytes: int
    selected: bool = True

# ── Size helpers ────────────────────────────────────────────────────────────

def du(path: Path) -> int:
    """Fast-ish recursive size via os.scandir. Returns bytes."""
    total = 0
    try:
        if path.is_file() or path.is_symlink():
            return path.stat().st_size
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if entry.is_file(follow_symlinks=False):
                        total += entry.stat().st_size
                    elif entry.is_dir(follow_symlinks=False):
                        total += du(Path(entry.path))
                except (PermissionError, OSError):
                    pass
    except (PermissionError, OSError):
        pass
    return total

def du_cached(path: Path) -> int:
    """Cached size lookup for directories. Results negated to distinguish from 0."""
    try:
        if path.exists():
            return du(path)
    except (PermissionError, OSError):
        pass
    return 0

# ── Scanners ────────────────────────────────────────────────────────────────

HOME = Path.home()

CATEGORIES_REGISTRY: Dict[str, JunkCategory] = {}


def register_category(key: str, name: str, description: str):
    CATEGORIES_REGISTRY[key] = JunkCategory(name=name, description=description)


def add_entry(cat_key: str, path: Path, label: Optional[str] = None, min_size: int = 0):
    """Scan path and add as JunkEntry if it exists and has content."""
    if not path.exists():
        return
    sz = du_cached(path)
    if sz <= min_size:
        return
    CATEGORIES_REGISTRY[cat_key].entries.append(
        JunkEntry(path=path, label=label or path.name, size_bytes=sz, selected=True)
    )


def scan_all_categories():
    CATEGORIES_REGISTRY.clear()

    # ── 1. User Cache Files ────────────────────────────────────────────────
    register_category(
        "user_cache",
        "Archivos de cache del usuario",
        "Archivos temporales usados por apps para acelerarse. Se pueden borrar sin riesgo.",
    )

    user_cache = HOME / "Library" / "Caches"
    try:
        if user_cache.exists():
            with os.scandir(user_cache) as it:
                for entry in sorted(it, key=lambda e: e.name.lower()):
                    p = Path(entry.path)
                    sz = du_cached(p)
                    if sz > 10_000_000:
                        add_entry("user_cache", p, label=entry.name)
    except (PermissionError, OSError):
        pass

    # ── 2. System Cache ────────────────────────────────────────────────────
    register_category(
        "system_cache",
        "Archivos de cache del sistema",
        "Caches a nivel sistema. Seguro limpiar, se regeneran.",
    )
    sys_cache = Path("/Library/Caches")
    try:
        if sys_cache.exists():
            with os.scandir(sys_cache) as it:
                for entry in sorted(it, key=lambda e: e.name.lower()):
                    p = Path(entry.path)
                    sz = du_cached(p)
                    if sz > 10_000_000:
                        add_entry("system_cache", p, label=entry.name)
    except (PermissionError, OSError):
        pass

    # ── 3. Log Files ───────────────────────────────────────────────────────
    register_category(
        "logs",
        "Archivos de registro (logs)",
        "Logs de apps y sistema. Pueden crecer bastante con el tiempo.",
    )
    for log_dir in [HOME / "Library" / "Logs", Path("/Library/Logs")]:
        try:
            if log_dir.exists():
                with os.scandir(log_dir) as it:
                    for entry in sorted(it, key=lambda e: e.name.lower()):
                        p = Path(entry.path)
                        sz = du_cached(p)
                        if sz > 10_000_000:
                            add_entry("logs", p, label=entry.name)
        except (PermissionError, OSError):
            pass

    # ── 4. Trash Bins ──────────────────────────────────────────────────────
    register_category(
        "trash",
        "Papeleras",
        "Archivos en la papelera (aún no vaciada permanentemente).",
    )
    for trash_path in [HOME / ".Trash", Path("/.Trashes")]:
        try:
            if trash_path.exists():
                with os.scandir(trash_path) as it:
                    for entry in sorted(it, key=lambda e: e.name.lower()):
                        p = Path(entry.path)
                        sz = du_cached(p)
                        if sz > 0:
                            add_entry("trash", p, label=entry.name)
        except (PermissionError, OSError):
            pass

    # ── 5. Xcode Junk ──────────────────────────────────────────────────────
    register_category(
        "xcode",
        "Basura de Xcode",
        "DerivedData, iOS DeviceSupport, archives antiguos.",
    )
    xcode_data = HOME / "Library" / "Developer" / "Xcode"
    for sub in ["DerivedData", "Archives", "iOS DeviceSupport"]:
        p = xcode_data / sub
        try:
            if p.exists():
                with os.scandir(p) as it:
                    for entry in sorted(it, key=lambda e: e.name.lower()):
                        ep = Path(entry.path)
                        sz = du_cached(ep)
                        if sz > 0:
                            add_entry("xcode", ep, label=f"[Xcode] {sub}/{entry.name}")
        except (PermissionError, OSError):
            pass

    # ── 6. Homebrew Cache ──────────────────────────────────────────────────
    register_category(
        "homebrew",
        "Caché de Homebrew",
        "Archivos descargados por Homebrew. `brew cleanup` también los limpia.",
    )
    brew_cache = HOME / "Library" / "Caches" / "Homebrew"
    if brew_cache.exists():
        sz = du_cached(brew_cache)
        if sz > 0:
            CATEGORIES_REGISTRY["homebrew"].entries.append(
                JunkEntry(path=brew_cache, label="Homebrew cache", size_bytes=sz, selected=True)
            )

    # ── 7. pip Cache ───────────────────────────────────────────────────────
    register_category(
        "pip",
        "Caché de pip",
        "Paquetes descargados por pip. Se vuelven a bajar si faltan.",
    )
    pip_cache = HOME / "Library" / "Caches" / "pip"
    if pip_cache.exists():
        sz = du_cached(pip_cache)
        if sz > 0:
            CATEGORIES_REGISTRY["pip"].entries.append(
                JunkEntry(path=pip_cache, label="pip cache", size_bytes=sz, selected=True)
            )

    # ── 8. npm Cache ───────────────────────────────────────────────────────
    register_category(
        "npm",
        "Caché de npm",
        "Paquetes cacheados por npm. `npm cache clean --force` también sirve.",
    )
    npm_cache = HOME / ".npm"
    if npm_cache.exists():
        sz = du_cached(npm_cache)
        if sz > 0:
            CATEGORIES_REGISTRY["npm"].entries.append(
                JunkEntry(path=npm_cache, label="npm cache", size_bytes=sz, selected=True)
            )

    # ── 9. Yarn Cache ──────────────────────────────────────────────────────
    register_category(
        "yarn",
        "Caché de Yarn",
        "Paquetes cacheados por Yarn.",
    )
    yarn_cache = HOME / "Library" / "Caches" / "Yarn"
    if yarn_cache.exists():
        sz = du_cached(yarn_cache)
        if sz > 0:
            CATEGORIES_REGISTRY["yarn"].entries.append(
                JunkEntry(path=yarn_cache, label="Yarn cache", size_bytes=sz, selected=True)
            )

    # ── 10. Gradle Cache ───────────────────────────────────────────────────
    register_category(
        "gradle",
        "Caché de Gradle",
        "Caché de builds Gradle (Android Studio, etc.). Puede ocupar muchos GB.",
    )
    gradle_dir = HOME / ".gradle" / "caches"
    if gradle_dir.exists():
        sz = du_cached(gradle_dir)
        if sz > 0:
            CATEGORIES_REGISTRY["gradle"].entries.append(
                JunkEntry(path=gradle_dir, label="Gradle caches", size_bytes=sz, selected=True)
            )

    # ── 11. CocoaPods Cache ────────────────────────────────────────────────
    register_category(
        "cocoapods",
        "Caché de CocoaPods",
        "Especs y pods cacheados. Se regeneran.",
    )
    pods = HOME / "Library" / "Caches" / "CocoaPods"
    if pods.exists():
        sz = du_cached(pods)
        if sz > 0:
            CATEGORIES_REGISTRY["cocoapods"].entries.append(
                JunkEntry(path=pods, label="CocoaPods cache", size_bytes=sz, selected=True)
            )

    # ── 12. Google Software ────────────────────────────────────────────────
    register_category(
        "google",
        "Caché de Google",
        "Caché de Chrome, Drive, etc.",
    )
    google_dirs = [
        HOME / "Library" / "Caches" / "Google",
        HOME / "Library" / "Google",
    ]
    for gd in google_dirs:
        try:
            if gd.exists():
                with os.scandir(gd) as it:
                    for entry in it:
                        ep = Path(entry.path)
                        sz = du_cached(ep)
                        if sz > 5_000_000:
                            CATEGORIES_REGISTRY["google"].entries.append(
                                JunkEntry(path=ep, label=f"Google/{entry.name}", size_bytes=sz, selected=True)
                            )
        except (PermissionError, OSError):
            pass

    # ── 13. Microsoft Teams Cache ──────────────────────────────────────────
    register_category(
        "teams",
        "Caché de Microsoft Teams",
        "Caché de Teams (logs, elementos multimedia).",
    )
    teams_cache = HOME / "Library" / "Application Support" / "Microsoft" / "Teams" / "Cache"
    if teams_cache.exists():
        sz = du_cached(teams_cache)
        if sz > 0:
            CATEGORIES_REGISTRY["teams"].entries.append(
                JunkEntry(path=teams_cache, label="Teams cache", size_bytes=sz, selected=True)
            )

    # ── 14. VSCode C++ Tools Cache ─────────────────────────────────────────
    register_category(
        "vscode_cpp",
        "Caché de VS Code C++",
        "Caché de IntelliSense de C/C++ en VS Code.",
    )
    vscpp = HOME / "Library" / "Caches" / "vscode-cpptools"
    if vscpp.exists():
        sz = du_cached(vscpp)
        if sz > 0:
            CATEGORIES_REGISTRY["vscode_cpp"].entries.append(
                JunkEntry(path=vscpp, label="vscode-cpptools cache", size_bytes=sz, selected=True)
            )

    # ── 15. CoreDevice Service Cache ───────────────────────────────────────
    register_category(
        "coredevice",
        "Caché de CoreDevice",
        "Caché de conexiones de dispositivos Apple.",
    )
    cd = HOME / "Library" / "Caches" / "com.apple.CoreDevice.CoreDeviceService"
    if cd.exists():
        sz = du_cached(cd)
        if sz > 0:
            CATEGORIES_REGISTRY["coredevice"].entries.append(
                JunkEntry(path=cd, label="CoreDevice cache", size_bytes=sz, selected=True)
            )

    # ── 16. Mail Downloads ─────────────────────────────────────────────────
    register_category(
        "mail",
        "Descargas de Mail",
        "Adjuntos y descargas de la app Mail.",
    )
    mail = HOME / "Library" / "Containers" / "com.apple.mail" / "Data" / "Library" / "Mail Downloads"
    if mail.exists():
        sz = du_cached(mail)
        if sz > 0:
            CATEGORIES_REGISTRY["mail"].entries.append(
                JunkEntry(path=mail, label="Mail downloads", size_bytes=sz, selected=True)
            )

    # ── 17. User Temporary Files ───────────────────────────────────────────
    register_category(
        "temp",
        "Archivos temporales",
        "Archivos en /tmp y ~/.tmp.",
    )
    for tmp in [Path("/tmp"), HOME / ".tmp"]:
        try:
            if tmp.exists():
                with os.scandir(tmp) as it:
                    for entry in it:
                        ep = Path(entry.path)
                        sz = du_cached(ep)
                        if sz > 1_000_000:
                            CATEGORIES_REGISTRY["temp"].entries.append(
                                JunkEntry(path=ep, label=f"tmp/{entry.name}", size_bytes=sz, selected=True)
                            )
        except (PermissionError, OSError):
            pass

    # ── 18. Old Downloads suggestions ──────────────────────────────────────
    register_category(
        "downloads_old",
        "Descargas antiguas (> 90 dias)",
        "Archivos en Descargas con más de 90 días de antigüedad.",
    )
    dl = HOME / "Downloads"
    try:
        if dl.exists():
            cutoff = datetime.now() - timedelta(days=90)
            with os.scandir(dl) as it:
                for entry in sorted(it, key=lambda e: e.name.lower()):
                    ep = Path(entry.path)
                    try:
                        st = ep.stat()
                        mtime = datetime.fromtimestamp(st.st_mtime)
                        if mtime < cutoff:
                            sz = du_cached(ep)
                            if sz > 0:
                                CATEGORIES_REGISTRY["downloads_old"].entries.append(
                                    JunkEntry(path=ep, label=f"Downloads/{entry.name} ({mtime.strftime('%Y-%m-%d')})",
                                              size_bytes=sz, selected=False)
                                    )
                    except OSError:
                        pass
    except (PermissionError, OSError):
        pass

    # ── 19. iOS Software Updates ───────────────────────────────────────────
    register_category(
        "ios_updates",
        "Actualizaciones de iOS descargadas",
        "Instaladores de iOS descargados y ya aplicados.",
    )
    ios_updates = HOME / "Library" / "iTunes" / "iPhone Software Updates"
    if ios_updates.exists():
        sz = du_cached(ios_updates)
        if sz > 0:
            CATEGORIES_REGISTRY["ios_updates"].entries.append(
                JunkEntry(path=ios_updates, label="iOS updates", size_bytes=sz, selected=True)
            )

    # ── 20. Time Machine local snapshots (info only) ───────────────────────
    register_category(
        "tm_snapshots",
        "Snapshots locales de Time Machine",
        "Snapshots locales. Se limpian con `tmutil deletelocalsnapshots /`.",
    )
    # Not auto-scanned; user can trigger via terminal separately

    # ── Remove categories with zero entries ─────────────────────────────────
    for key in list(CATEGORIES_REGISTRY.keys()):
        if not CATEGORIES_REGISTRY[key].entries:
            del CATEGORIES_REGISTRY[key]


# ── Display helpers ─────────────────────────────────────────────────────────

def print_category(cat: JunkCategory, indent: int = 2):
    pref = " " * indent
    n = cat.selected_count
    t = cat.total_bytes if n > 0 else 0
    print(f"{pref}{BOLD}{cat.name}{RST}  {DIM}({n} elementos, {fmt_size(t)}){RST}")
    if cat.description:
        print(f"{pref}{DIM}{cat.description}{RST}")


def print_entries(cat: JunkCategory, show_all: bool = False):
    for i, e in enumerate(cat.entries, 1):
        mark = f"{GREEN}✔{RST}" if e.selected else f"{RED}✘{RST}"
        path_display = str(e.path)
        if len(path_display) > 80:
            path_display = "..." + path_display[-77:]
        if show_all or e.selected:
            print(f"     [{mark}] {fmt_size(e.size_bytes):>10}  {DIM}{path_display}{RST}")


# ── Interactive menu ────────────────────────────────────────────────────────

def prompt_yn(msg: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    r = input(f"  {msg} [{d}]: ").strip().lower()
    if not r:
        return default
    return r in ("y", "yes", "s", "si", "sí")


def menu_main() -> str:
    """Returns 'scan', 'review', 'clean', 'quit'."""
    clear()
    banner()
    print(f"  {BOLD}Menú principal{RST}\n")
    print(f"  {YELLOW}[s]{RST}   Escanear sistema (detectar basura)")
    print(f"  {YELLOW}[r]{RST}   Revisar / seleccionar qué limpiar")
    print(f"  {YELLOW}[c]{RST}   Limpiar todo lo seleccionado  {RED}(¡irreversible!){RST}")
    print(f"  {YELLOW}[a]{RST}   Auto-limpieza (escanear + limpiar todo sin preguntar)")
    print(f"  {YELLOW}[q]{RST}   Salir\n")
    ch = input(f"  {CYAN}Elegir [{BOLD}s,r,c,a,q{RST}{CYAN}]:{RST} ").strip().lower()
    if ch in ("s", "scan"):
        return "scan"
    elif ch in ("r", "review", "revisar"):
        return "review"
    elif ch in ("c", "clean", "limpiar"):
        return "clean"
    elif ch in ("a", "auto"):
        return "auto"
    elif ch in ("q", "quit", "salir"):
        return "quit"
    return "unknown"


def menu_summary():
    """Show total summary of selected items."""
    clear()
    banner()
    total_bytes = 0
    total_items = 0
    print(f"  {BOLD}Resumen de basura detectada{RST}\n")
    for key, cat in CATEGORIES_REGISTRY.items():
        if not cat.entries:
            continue
        print_category(cat)
        print()
        total_bytes += cat.total_bytes
        total_items += cat.selected_count
    print(f"  {'─' * 55}")
    print(f"  {BOLD}TOTAL: {total_items} elementos seleccionados | {fmt_size(total_bytes)}{RST}\n")
    return total_items, total_bytes


def menu_review():
    """Interactive review: select/deselect categories and entries."""
    while True:
        clear()
        banner()
        print(f"  {BOLD}Revisar elementos a limpiar{RST}\n")
        keys = list(CATEGORIES_REGISTRY.keys())
        for i, key in enumerate(keys, 1):
            cat = CATEGORIES_REGISTRY[key]
            sel = cat.selected_count
            total = len(cat.entries)
            nbytes = cat.total_bytes
            icon = f"{GREEN}✔{RST}" if sel == total and total > 0 else f"{YELLOW}~{RST}" if sel > 0 else f"{RED}✘{RST}"
            print(f"  {CYAN}{i:>2}{RST}. [{icon}] {cat.name}  {DIM}({sel}/{total}, {fmt_size(nbytes)}){RST}")

        total_all = sum(c.total_bytes for c in CATEGORIES_REGISTRY.values())
        total_items = sum(c.selected_count for c in CATEGORIES_REGISTRY.values())
        print(f"\n  {DIM}TOTAL seleccionado: {total_items} elementos, {fmt_size(total_all)}{RST}")
        print(f"\n  {YELLOW}[1-{len(keys)}]{RST}  Detalle de categoria")
        print(f"  {YELLOW}[t]{RST}    Seleccionar todo")
        print(f"  {YELLOW}[n]{RST}    Deseleccionar todo")
        print(f"  {YELLOW}[v]{RST}    Volver al menu principal\n")

        ch = input(f"  {CYAN}Elegir:{RST} ").strip().lower()
        if ch in ("v", "volver", "q"):
            return

        if ch == "t":
            for k in CATEGORIES_REGISTRY.values():
                for e in k.entries:
                    e.selected = True
            continue

        if ch == "n":
            for k in CATEGORIES_REGISTRY.values():
                for e in k.entries:
                    e.selected = False
            continue

        try:
            idx = int(ch) - 1
            if 0 <= idx < len(keys):
                key = keys[idx]
                cat = CATEGORIES_REGISTRY[key]
                review_category(key, cat)
        except ValueError:
            pass


def review_category(key: str, cat: JunkCategory):
    while True:
        clear()
        banner()
        print(f"  {BOLD}{cat.name}{RST}")
        print(f"  {DIM}{cat.description}{RST}\n")
        print(f"  {YELLOW}[s]{RST}  Seleccionar todos")
        print(f"  {YELLOW}[d]{RST}  Deseleccionar todos")
        print()

        entries = cat.entries
        for i, e in enumerate(entries, 1):
            mark = f"{GREEN}✔{RST}" if e.selected else f"{RED}✘{RST}"
            path_display = str(e.path)
            home_str = str(HOME)
            if path_display.startswith(home_str):
                path_display = "~" + path_display[len(home_str):]
            if len(path_display) > 90:
                path_display = "..." + path_display[-87:]
            print(f"  {CYAN}{i:>3}{RST}. [{mark}] {fmt_size(e.size_bytes):>10}  {DIM}{path_display}{RST}")

        print(f"\n  {YELLOW}[v]{RST}  Volver")
        ch = input(f"\n  {CYAN}Elegir numero para toggle o comando:{RST} ").strip().lower()

        if ch in ("v", "volver", "q"):
            return
        elif ch == "s":
            for e in entries:
                e.selected = True
        elif ch == "d":
            for e in entries:
                e.selected = False
        else:
            try:
                idx = int(ch) - 1
                if 0 <= idx < len(entries):
                    entries[idx].selected = not entries[idx].selected
            except ValueError:
                pass


# ── Deletion engine ─────────────────────────────────────────────────────────

def _rm_rf(p: Path) -> bool:
    """Delete a file or directory. Returns True on success."""
    try:
        if p.is_symlink():
            p.unlink()
        elif p.is_dir():
            shutil.rmtree(str(p), ignore_errors=False)
        elif p.is_file():
            p.unlink()
        else:
            return False
        return True
    except (OSError, PermissionError) as exc:
        print(f"    {RED}Error al borrar {p}: {exc}{RST}")
        return False


def execute_cleanup(entries: List[JunkEntry]) -> Tuple[int, int]:
    """Delete selected entries. Returns (deleted_count, freed_bytes)."""
    deleted = 0
    freed = 0
    for e in entries:
        if not e.selected:
            continue
        path = e.path
        print(f"  {YELLOW}Borrando{RST} {DIM}{path}{RST} ...", end=" ")
        if _rm_rf(path):
            deleted += 1
            freed += e.size_bytes
            print(f"{GREEN}OK{RST}")
        else:
            print(f"{RED}FAIL{RST}")
    return deleted, freed


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    if platform.system() != "Darwin":
        print(f"{RED}Este script solo funciona en macOS.{RST}")
        sys.exit(1)

    scanned = False

    while True:
        action = menu_main()
        if action == "quit":
            print(f"\n  {GREEN}¡Adiós!{RST}\n")
            break

        elif action == "scan":
            clear()
            banner()
            print(f"  {YELLOW}Escaneando sistema...{RST} (puede tardar varios segundos)\n")
            dots = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            import threading, time

            done_flag = [False]

            def spinner():
                i = 0
                while not done_flag[0]:
                    sys.stdout.write(f"\r  {CYAN}{dots[i % len(dots)]}{RST} Escaneando...")
                    sys.stdout.flush()
                    i += 1
                    time.sleep(0.08)
                sys.stdout.write("\r" + " " * 40 + "\r")
                sys.stdout.flush()

            t = threading.Thread(target=spinner)
            t.start()
            scan_all_categories()
            done_flag[0] = True
            t.join()
            scanned = True
            print(f"  {GREEN}✔ Escaneo completado.{RST}")
            total_items, total_bytes = menu_summary()
            input(f"\n  {DIM}Presiona ENTER para continuar...{RST}")

        elif action == "review":
            if not scanned:
                print(f"\n  {YELLOW}Primero debes escanear.RST")
                input(f"  {DIM}Presiona ENTER para continuar...{RST}")
                continue
            menu_review()

        elif action in ("clean", "auto"):
            if action == "auto" and not scanned:
                scan_all_categories()
                scanned = True

            if action == "clean" and not scanned:
                print(f"\n  {YELLOW}Primero debes escanear.RST")
                input(f"  {DIM}Presiona ENTER para continuar...{RST}")
                continue

            if action == "auto":
                # Select all
                for cat in CATEGORIES_REGISTRY.values():
                    for e in cat.entries:
                        e.selected = True

            total_items, total_bytes = menu_summary()
            if total_items == 0:
                print(f"  {YELLOW}Nada seleccionado para limpiar.{RST}")
                input(f"\n  {DIM}Presiona ENTER para continuar...{RST}")
                continue

            if action == "clean":
                print(f"\n  {RED}{BOLD}¡ATENCIÓN! Se borrarán {total_items} elementos ({fmt_size(total_bytes)}).{RST}")
                print(f"  {RED}Esta acción NO se puede deshacer.{RST}\n")
                if not prompt_yn(f"{BOLD}¿Confirmas la eliminación?{RST}", default=False):
                    print(f"  {YELLOW}Cancelado.{RST}")
                    input(f"\n  {DIM}Presiona ENTER para continuar...{RST}")
                    continue
            else:
                # auto mode
                print(f"\n  {YELLOW}Auto-limpieza: borrando {total_items} elementos ({fmt_size(total_bytes)})...{RST}\n")

            all_entries = [e for cat in CATEGORIES_REGISTRY.values() for e in cat.entries if e.selected]
            deleted, freed = execute_cleanup(all_entries)

            # Empty trash properly
            try:
                subprocess.run(["osascript", "-e", 'tell application "Finder" to empty trash'],
                               capture_output=True)
            except Exception:
                pass

            print(f"\n  {GREEN}{BOLD}✔ Limpieza completada.{RST}")
            print(f"  {GREEN}  Se borraron {deleted} elementos liberando {fmt_size(freed)}.{RST}")
            input(f"\n  {DIM}Presiona ENTER para continuar...{RST}")
            # Rescan after clean
            scanned = False

        else:
            print(f"\n  {RED}Opción no válida.{RST}")
            input(f"  {DIM}Presiona ENTER para continuar...{RST}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}Interrumpido por el usuario.{RST}\n")
        sys.exit(0)
