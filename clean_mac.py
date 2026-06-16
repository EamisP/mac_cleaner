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
import curses
import time
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta

def fmt_size(b: int) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"

# ── Curses color pairs ──────────────────────────────────────────────────────
# We'll init them inside curses_main

def _draw_banner(scr, y=0):
    """Draw Mac Cleaner banner inside a curses window."""
    h, w = scr.getmaxyx()
    box_w = min(54, w - 2)
    box_x = max(0, (w - box_w) // 2)
    try:
        scr.attron(curses.color_pair(5))
        scr.addstr(y, box_x, "╔" + "═" * (box_w - 2) + "╗")
        title = "  🧹  M A C   C L E A N E R  "
        tx = max(0, (w - len(title)) // 2)
        scr.addstr(y + 1, tx, title, curses.A_BOLD)
        scr.addstr(y + 2, box_x, "╚" + "═" * (box_w - 2) + "╝")
        scr.attroff(curses.color_pair(5))
    except curses.error:
        pass
    return y + 4

def _draw_footer(scr, keys_help):
    """Draw keybinding hints at bottom."""
    h, w = scr.getmaxyx()
    try:
        scr.attron(curses.color_pair(8))
        _safe_addstr(scr, h - 2, 0, " " * (w - 1))
        _safe_addstr(scr, h - 2, max(0, (w - len(keys_help)) // 2), keys_help)
        scr.attroff(curses.color_pair(8))
    except curses.error:
        pass

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


# ═══════════════════════════════════════════════════════════════════════════════
# CURSES TUI
# ═══════════════════════════════════════════════════════════════════════════════

def _safe_addstr(scr, y, x, text, *args):
    """Add string to curses window, clipping to screen bounds."""
    h, w = scr.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    text = text[:max(0, w - x)]
    if not text:
        return
    try:
        scr.addstr(y, x, text, *args)
    except curses.error:
        pass

def _draw_list(scr, start_y, items, current_idx, scroll_offset, selected_fn=None,
               show_checkbox=True):
    """Draw a scrollable list. Returns number of lines drawn.
    
    items: list of (label, ...) tuples or strings
    selected_fn: optional function(item) -> bool for checkbox state
    """
    h, w = scr.getmaxyx()
    max_visible = max(1, h - start_y - 4)  # leave room for footer
    drawn = 0
    for i, item in enumerate(items):
        if i < scroll_offset:
            continue
        if drawn >= max_visible:
            break
        y = start_y + drawn
        label = item[0] if isinstance(item, tuple) else item
        is_current = (i == current_idx)
        
        if show_checkbox and selected_fn:
            sel = selected_fn(item)
            checkbox = "[✔]" if sel else "[ ]"
        else:
            checkbox = ""
            sel = False
        
        # Truncate label to fit
        avail = w - 4 - len(checkbox) - 3
        if len(label) > avail:
            label = label[:avail - 1] + "…"
        
        line = f" {checkbox} {label}" if checkbox else f"  {label}"
        
        if is_current:
            scr.attron(curses.A_REVERSE)
            _safe_addstr(scr, y, 0, line.ljust(w - 1))
            scr.attroff(curses.A_REVERSE)
        elif sel:
            scr.attron(curses.color_pair(2))
            _safe_addstr(scr, y, 0, line)
            scr.attroff(curses.color_pair(2))
        else:
            scr.attron(curses.color_pair(8))
            _safe_addstr(scr, y, 0, line)
            scr.attroff(curses.color_pair(8))
        drawn += 1
    
    return drawn

def _menu_checkboxes(scr, title, items, selected_fn, toggle_fn,
                     select_all_fn=None, deselect_all_fn=None,
                     extra_footer="", show_checkbox=True,
                     item_formatter=None):
    """Menu with checkboxes. Arrow keys + space to toggle.
    items: list of tuples (..., data)
    item_formatter: optional callable(item) -> (label, ...) for dynamic labels
    Returns None to go back.
    """
    current = 0
    scroll = 0
    h, w = scr.getmaxyx()
    
    while True:
        scr.clear()
        
        display = [item_formatter(it) for it in items] if item_formatter else items
        
        y = _draw_banner(scr)
        scr.attron(curses.A_BOLD)
        _safe_addstr(scr, y, 2, title)
        scr.attroff(curses.A_BOLD)
        y += 2
        
        # Show totals
        total_selected = sum(1 for item in items if selected_fn(item))
        total_items = len(items)
        total_bytes = sum(item[2] for item in display if selected_fn(item) and len(item) > 2 and isinstance(item[2], (int, float)))
        
        scr.attron(curses.color_pair(8))
        _safe_addstr(scr, y, 2, f"{total_selected}/{total_items} seleccionados  |  {fmt_size(total_bytes)}" if total_bytes > 0 else f"{total_selected}/{total_items} seleccionados")
        scr.attroff(curses.color_pair(8))
        y += 2
        
        _draw_list(scr, y, display, current, scroll, selected_fn=selected_fn,
                  show_checkbox=show_checkbox)
        
        footer = f"↑↓ flechas  [espacio] toggle  {extra_footer}  esc/q volver"
        if select_all_fn:
            footer = "↑↓ flechas  [espacio] toggle  t:todo n:nada  esc/q volver"
        _draw_footer(scr, footer)
        scr.refresh()
        
        key = scr.getch()
        if key == curses.KEY_RESIZE:
            scr.clear()
            h, w = scr.getmaxyx()
            scroll = min(scroll, max(0, len(items) - 1))
            continue
        elif key in (curses.KEY_UP, ord('k')):
            if current > 0:
                current -= 1
                if current < scroll:
                    scroll = current
        elif key in (curses.KEY_DOWN, ord('j')):
            if current < len(items) - 1:
                current += 1
                max_vis = max(1, h - (y + 2) - 4)
                if current >= scroll + max_vis:
                    scroll = current - max_vis + 1
        elif key == ord(' '):
            if 0 <= current < len(items):
                toggle_fn(items[current])
        elif key in (10, 13, curses.KEY_ENTER):
            return current
        elif key in (27, ord('q'), ord('v')):
            return None
        elif key in (ord('t'), ord('s')):
            if select_all_fn:
                select_all_fn()
        elif key in (ord('n'), ord('d')):
            if deselect_all_fn:
                deselect_all_fn()

def _confirm_dialog(scr, msg, default=False):
    """Show a yes/no confirmation dialog. Returns bool."""
    h, w = scr.getmaxyx()
    selected = 0 if default else 1  # 0=Yes, 1=No
    
    while True:
        scr.clear()
        y = _draw_banner(scr)
        y += 1
        scr.attron(curses.color_pair(3) | curses.A_BOLD)
        _safe_addstr(scr, y, max(0, (w - len(msg)) // 2), msg)
        scr.attroff(curses.color_pair(3) | curses.A_BOLD)
        y += 3
        
        options = ["  Sí, borrar  ", "  No, cancelar  "]
        gap = "    "
        row = options[0] + gap + options[1]
        row_x = max(0, (w - len(row)) // 2)
        x0 = row_x
        x1 = row_x + len(options[0]) + len(gap)
        for i, (opt, x) in enumerate([(options[0], x0), (options[1], x1)]):
            if i == selected:
                scr.attron(curses.A_REVERSE)
                _safe_addstr(scr, y, x, opt)
                scr.attroff(curses.A_REVERSE)
            else:
                _safe_addstr(scr, y, x, opt)
        
        _draw_footer(scr, "←→ seleccionar  ↵ confirmar")
        scr.refresh()
        
        key = scr.getch()
        if key in (curses.KEY_LEFT, ord('h')):
            selected = max(0, selected - 1)
        elif key in (curses.KEY_RIGHT, ord('l')):
            selected = min(1, selected + 1)
        elif key in (10, 13, curses.KEY_ENTER):
            return selected == 0
        elif key in (27, ord('q')):
            return False

def _show_message(scr, lines, wait=True):
    """Show a message screen. Returns when key pressed or immediately."""
    scr.clear()
    y = _draw_banner(scr)
    y += 1
    for line in lines:
        _safe_addstr(scr, y, 2, line)
        y += 1
    if wait:
        _draw_footer(scr, "Presiona cualquier tecla para continuar...")
    scr.refresh()
    if wait:
        scr.getch()

def _show_summary(scr):
    """Show scan results summary. Returns total_items, total_bytes."""
    scr.clear()
    y = _draw_banner(scr)
    scr.attron(curses.A_BOLD)
    _safe_addstr(scr, y, 2, "Resumen de basura detectada")
    scr.attroff(curses.A_BOLD)
    y += 2
    
    total_bytes = 0
    total_items = 0
    h, w = scr.getmaxyx()
    max_vis = h - y - 5
    
    for key, cat in CATEGORIES_REGISTRY.items():
        if not cat.entries:
            continue
        n = cat.selected_count
        t = cat.total_bytes if n > 0 else 0
        
        if y - 2 < max_vis:
            scr.attron(curses.A_BOLD)
            icon = "✔" if n == len(cat.entries) else "~" if n > 0 else "✘"
            _safe_addstr(scr, y, 2, f"  [{icon}] {cat.name}")
            scr.attroff(curses.A_BOLD)
            scr.attron(curses.color_pair(8))
            _safe_addstr(scr, y + 1, 4, f"{n} elementos, {fmt_size(t)}")
            scr.attroff(curses.color_pair(8))
            y += 3
        total_bytes += cat.total_bytes
        total_items += cat.selected_count
    
    y += 1
    scr.attron(curses.color_pair(3) | curses.A_BOLD)
    _safe_addstr(scr, y, 2, "─" * min(55, w - 4))
    _safe_addstr(scr, y + 1, 2, f"TOTAL: {total_items} elementos seleccionados | {fmt_size(total_bytes)}")
    scr.attroff(curses.color_pair(3) | curses.A_BOLD)
    
    _draw_footer(scr, "Presiona cualquier tecla para continuar...")
    scr.refresh()
    scr.getch()
    return total_items, total_bytes

def _scan_with_spinner(scr):
    """Run scan with a status display in curses."""
    scr.clear()
    h, w = scr.getmaxyx()
    y = _draw_banner(scr)
    scr.attron(curses.A_BOLD)
    _safe_addstr(scr, y, 2, "Escaneando sistema...")
    scr.attroff(curses.A_BOLD)
    _draw_footer(scr, "Esto puede tardar varios segundos...")
    scr.refresh()
    
    scan_all_categories()
    
    y = _draw_banner(scr)
    scr.attron(curses.color_pair(2) | curses.A_BOLD)
    _safe_addstr(scr, y, 2, "✔ Escaneo completado.")
    scr.attroff(curses.color_pair(2) | curses.A_BOLD)
    scr.refresh()
    time.sleep(0.5)
    return True

def _run_cleanup(scr, all_entries):
    """Run cleanup with progress in curses."""
    scr.clear()
    h, w = scr.getmaxyx()
    y = _draw_banner(scr)
    scr.attron(curses.A_BOLD)
    _safe_addstr(scr, y, 2, "Limpiando archivos...")
    scr.attroff(curses.A_BOLD)
    y += 2
    
    deleted = 0
    freed = 0
    total = len([e for e in all_entries if e.selected])
    
    for e in all_entries:
        if not e.selected:
            continue
        path_str = str(e.path)
        home_str = str(HOME)
        if path_str.startswith(home_str):
            path_str = "~" + path_str[len(home_str):]
        if len(path_str) > w - 10:
            path_str = "..." + path_str[-(w - 13):]
        
        _safe_addstr(scr, y, 2, f"  Borrando {path_str}...")
        scr.refresh()
        
        if _rm_rf(e.path):
            deleted += 1
            freed += e.size_bytes
            _safe_addstr(scr, y, 2, f"  {path_str}  ✔")
        else:
            _safe_addstr(scr, y, 2, f"  {path_str}  ✘")
        scr.refresh()
        y += 1
        
        if y >= h - 3:
            scr.clear()
            y = _draw_banner(scr)
            scr.attron(curses.A_BOLD)
            _safe_addstr(scr, y, 2, "Limpiando archivos...")
            scr.attroff(curses.A_BOLD)
            y += 2
    
    # Empty trash via AppleScript
    try:
        subprocess.run(["osascript", "-e", 'tell application "Finder" to empty trash'],
                       capture_output=True)
    except Exception:
        pass
    
    y += 1
    scr.attron(curses.color_pair(2) | curses.A_BOLD)
    _safe_addstr(scr, y, 2, f"✔ Limpieza completada: {deleted} elementos, {fmt_size(freed)} liberados.")
    scr.attroff(curses.color_pair(2) | curses.A_BOLD)
    
    _draw_footer(scr, "Presiona cualquier tecla para continuar...")
    scr.refresh()
    scr.getch()
    return deleted, freed


# ═══════════════════════════════════════════════════════════════════════════════
# CURSES MENU SCREENS
# ═══════════════════════════════════════════════════════════════════════════════

def _curses_main_menu(scr):
    """Main menu. Returns action string: 'scan','review','clean','auto','quit'."""
    options = [
        ("Escanear sistema (detectar basura)", "scan"),
        ("Revisar / seleccionar qué limpiar", "review"),
        ("Limpiar todo lo seleccionado  ⚠ irreversible", "clean"),
        ("Auto-limpieza (escanear + limpiar todo)", "auto"),
        ("Salir", "quit"),
    ]
    
    current = 0
    scroll = 0
    h, w = scr.getmaxyx()
    
    while True:
        scr.clear()
        y = _draw_banner(scr)
        scr.attron(curses.A_BOLD)
        _safe_addstr(scr, y, 2, "Menú principal")
        scr.attroff(curses.A_BOLD)
        y += 2
        
        # Show selected totals if scanned
        if CATEGORIES_REGISTRY:
            total_bytes = sum(c.total_bytes for c in CATEGORIES_REGISTRY.values())
            total_items = sum(c.selected_count for c in CATEGORIES_REGISTRY.values())
            if total_items > 0:
                scr.attron(curses.color_pair(3))
                _safe_addstr(scr, y, 2, f"  {total_items} elementos seleccionados ({fmt_size(total_bytes)})")
                scr.attroff(curses.color_pair(3))
                y += 2
        
        _draw_list(scr, y, options, current, scroll, show_checkbox=False)
        
        _draw_footer(scr, "↑↓ navegar  ↵ seleccionar  q salir")
        scr.refresh()
        
        key = scr.getch()
        if key in (curses.KEY_UP, ord('k')):
            if current > 0:
                current -= 1
                if current < scroll:
                    scroll = current
        elif key in (curses.KEY_DOWN, ord('j')):
            if current < len(options) - 1:
                current += 1
                max_vis = max(1, h - (y + 2) - 4)
                if current >= scroll + max_vis:
                    scroll = current - max_vis + 1
        elif key in (10, 13, curses.KEY_ENTER):
            ch = options[current][1]
            # Quick key shortcuts also work
            return ch
        elif key in (27, ord('q')):
            return "quit"
        elif key == ord('s'):
            return "scan"
        elif key == ord('r'):
            return "review"
        elif key == ord('c'):
            return "clean"
        elif key == ord('a'):
            return "auto"
        elif key == curses.KEY_RESIZE:
            scr.clear()
            h, w = scr.getmaxyx()
            scroll = min(scroll, max(0, len(options) - 1))

def _curses_review(scr):
    """Review categories screen."""
    while True:
        keys = list(CATEGORIES_REGISTRY.keys())
        
        # Pass bare keys; formatter generates live labels on each redraw
        items = [(key,) for key in keys]
        
        def format_item(it):
            key = it[0]
            cat = CATEGORIES_REGISTRY[key]
            sel = cat.selected_count
            total = len(cat.entries)
            icon = "✔" if sel == total and total > 0 else "~" if sel > 0 else "✘"
            return (f"[{icon}] {cat.name}  ({sel}/{total}, {fmt_size(cat.total_bytes)})", key)
        
        result = _menu_checkboxes(
            scr,
            "Revisar elementos a limpiar",
            items,
            selected_fn=lambda item: CATEGORIES_REGISTRY[item[-1]].selected_count > 0,
            toggle_fn=lambda item: _toggle_category(CATEGORIES_REGISTRY[item[-1]]),
            select_all_fn=lambda: _select_all_except_downloads(),
            deselect_all_fn=lambda: _deselect_all(),
            extra_footer="↵ ver detalle",
            show_checkbox=False,
            item_formatter=format_item
        )
        
        if result is None:
            return
        
        # Enter pressed: go into category detail
        idx = result
        if 0 <= idx < len(keys):
            _curses_review_category(scr, keys[idx], CATEGORIES_REGISTRY[keys[idx]])

def _select_all_except_downloads():
    for key, k in CATEGORIES_REGISTRY.items():
        if key == "downloads_old":
            continue
        for e in k.entries:
            e.selected = True

def _deselect_all():
    for k in CATEGORIES_REGISTRY.values():
        for e in k.entries:
            e.selected = False

def _toggle_category(cat):
    """Toggle all entries in a category."""
    if all(e.selected for e in cat.entries):
        for e in cat.entries:
            e.selected = False
    else:
        for e in cat.entries:
            e.selected = True

def _curses_review_category(scr, key, cat):
    """Review entries within a category."""
    entries = cat.entries
    home_str = str(HOME)
    
    def make_label(e):
        path_str = str(e.path)
        if path_str.startswith(home_str):
            path_str = "~" + path_str[len(home_str):]
        if len(path_str) > 60:
            path_str = "..." + path_str[-57:]
        return f"{fmt_size(e.size_bytes):>10}  {path_str}"
    
    items = [(make_label(e), e) for e in entries]
    
    def sel_fn(item):
        return item[1].selected
    
    def toggle_fn(item):
        item[1].selected = not item[1].selected
    
    def sel_all():
        for e in entries:
            e.selected = True
    
    def desel_all():
        for e in entries:
            e.selected = False
    
    current = 0
    scroll = 0
    h, w = scr.getmaxyx()
    
    while True:
        scr.clear()
        y = _draw_banner(scr)
        scr.attron(curses.A_BOLD)
        _safe_addstr(scr, y, 2, cat.name)
        scr.attroff(curses.A_BOLD)
        scr.attron(curses.color_pair(8))
        _safe_addstr(scr, y + 1, 2, cat.description[:w - 4])
        scr.attroff(curses.color_pair(8))
        y += 3
        
        _draw_list(scr, y, items, current, scroll, selected_fn=sel_fn)
        
        _draw_footer(scr, "↑↓ flechas  [espacio] toggle  s:todo d:nada  esc/q volver")
        scr.refresh()
        
        key_press = scr.getch()
        if key_press == curses.KEY_RESIZE:
            scr.clear()
            h, w = scr.getmaxyx()
            scroll = min(scroll, max(0, len(items) - 1))
            continue
        elif key_press in (curses.KEY_UP, ord('k')):
            if current > 0:
                current -= 1
                if current < scroll:
                    scroll = current
        elif key_press in (curses.KEY_DOWN, ord('j')):
            if current < len(items) - 1:
                current += 1
                max_vis = max(1, h - (y + 2) - 4)
                if current >= scroll + max_vis:
                    scroll = current - max_vis + 1
        elif key_press == ord(' '):
            if 0 <= current < len(items):
                toggle_fn(items[current])
        elif key_press in (27, ord('q'), ord('v')):
            return
        elif key_press in (ord('s'),):
            sel_all()
        elif key_press in (ord('d'), ord('n')):
            desel_all()


# ═══════════════════════════════════════════════════════════════════════════════
# CURSES MAIN LOOP
# ═══════════════════════════════════════════════════════════════════════════════

def _curses_main(scr):
    """Main curses loop."""
    curses.curs_set(0)
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_RED, -1)
    curses.init_pair(5, curses.COLOR_MAGENTA, -1)
    curses.init_pair(7, curses.COLOR_WHITE, -1)
    curses.init_pair(8, curses.COLOR_WHITE, -1)  # dim text
    
    scanned = False
    
    while True:
        action = _curses_main_menu(scr)
        
        if action == "quit":
            scr.clear()
            y = _draw_banner(scr)
            scr.attron(curses.color_pair(2) | curses.A_BOLD)
            _safe_addstr(scr, y, 2, "¡Adiós!")
            scr.attroff(curses.color_pair(2) | curses.A_BOLD)
            scr.refresh()
            time.sleep(0.8)
            return
        
        elif action == "scan":
            _scan_with_spinner(scr)
            scanned = True
            _show_summary(scr)
        
        elif action == "review":
            if not scanned:
                _show_message(scr, [
                    "Primero debes escanear el sistema.",
                    "",
                    "Selecciona 'Escanear sistema' en el menú principal."
                ])
                continue
            _curses_review(scr)
        
        elif action in ("clean", "auto"):
            if action == "auto" and not scanned:
                _scan_with_spinner(scr)
                scanned = True
            
            if action == "clean" and not scanned:
                _show_message(scr, [
                    "Primero debes escanear el sistema.",
                    "",
                    "Selecciona 'Escanear sistema' en el menú principal."
                ])
                continue
            
            if action == "auto":
                _select_all_except_downloads()
            
            all_entries = [e for cat in CATEGORIES_REGISTRY.values() for e in cat.entries]
            total_items = sum(1 for e in all_entries if e.selected)
            total_bytes = sum(e.size_bytes for e in all_entries if e.selected)
            
            if total_items == 0:
                _show_message(scr, ["Nada seleccionado para limpiar."])
                continue
            
            if action == "clean":
                if not _confirm_dialog(scr, f"¿Borrar {total_items} elementos ({fmt_size(total_bytes)})?  Esta acción NO se puede deshacer."):
                    continue
            
            _run_cleanup(scr, all_entries)
            scanned = False


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
    except (OSError, PermissionError):
        return False


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    if platform.system() != "Darwin":
        print("Este script solo funciona en macOS.")
        sys.exit(1)
    
    curses.wrapper(_curses_main)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.\n")
        sys.exit(0)
