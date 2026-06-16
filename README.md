# Mac Cleaner

Terminal-based system junk cleaner for macOS. Scans common cache and log locations, shows what can be safely deleted, and lets you pick what to remove.

No dependencies beyond Python 3. No subscriptions, no bloat.

## What it cleans

| Category | Location |
|---|---|
| User caches | `~/Library/Caches/*` (Gradle, Homebrew, pip, CocoaPods, Google, Teams, VS Code, Yarn, etc.) |
| System caches | `/Library/Caches/*` |
| Log files | `~/Library/Logs`, `/Library/Logs` |
| Trash bins | `~/.Trash`, `/.Trashes` |
| Xcode junk | DerivedData, iOS DeviceSupport, Archives |
| Homebrew cache | `~/Library/Caches/Homebrew` |
| pip cache | `~/Library/Caches/pip` |
| npm cache | `~/.npm` |
| Yarn cache | `~/Library/Caches/Yarn` |
| Gradle cache | `~/.gradle/caches` |
| CocoaPods cache | `~/Library/Caches/CocoaPods` |
| Google cache | `~/Library/Caches/Google`, `~/Library/Google` |
| Teams cache | Teams cache folder |
| VS Code C++ | `~/Library/Caches/vscode-cpptools` |
| CoreDevice | Apple device connection cache |
| Mail downloads | Mail app attachments and downloads |
| Temporary files | `/tmp`, `~/.tmp` |
| Old downloads | `~/Downloads` files older than 90 days (opt-in) |
| iOS updates | Downloaded iOS installers already applied |

20 categories in total, all skip SIP-protected directories automatically.

## Usage

```bash
python3 clean_mac.py
```

### Menu options

- **s** -- Scan system for junk. First step, required before reviewing or cleaning.
- **r** -- Review what was found. Toggle categories or individual entries on/off.
- **c** -- Clean everything selected. Asks for confirmation.
- **a** -- Auto-clean (scan + delete everything, no confirmation).
- **q** -- Quit.

### Typical flow

1. Press `s` to scan. Takes a few seconds while it walks the filesystem.
2. Press `r` to review. Navigate categories with number keys, toggle items, go back with `v`.
3. Press `c` to clean. Confirm with `y`.
4. Done.

## Requirements

- macOS (the script checks at startup)
- Python 3.7 or later
- No pip packages needed -- standard library only

## Safety

- The script never deletes anything outside the explicitly listed cache/log/temp directories.
- SIP-protected paths (System Integrity Protection) are skipped automatically.
- Old Downloads are **not pre-selected** -- you must opt in.
- Confirmation is required before any deletion (except `auto` mode).

## Disclaimer

Deletions are irreversible. Review what you are removing before confirming. If in doubt, deselect that item. The author is not responsible for data loss.

VirusTotal scan: https://www.virustotal.com/gui/file/940c724db8f3327cf372ae999dcab3466f15e51c0ae60804a197ed5dcab84aec/detection

## License

MIT
