# OmniFetch — Native Desktop Download Manager

OmniFetch is a high-speed, native Windows desktop download manager built with **PySide6 (Qt 6)**, **aiohttp**, and **libtorrent**, featuring a **3-Stage CyberShield Security Gate** connecting directly to the local offline security suite.

---

## Key Features (Phase 1 Implemented)

1. **Multi-Segment HTTP/HTTPS Engine:**
   - Up to 16 parallel Range chunk connections.
   - Crash-proof pause & resume backed by an SQLite WAL database (`PRAGMA journal_mode = WAL;`).
   - Dynamic segment division for large files with live smoothed speed and ETA estimation.
2. **Hidden Staging Containment (`.staging/`):**
   - Active chunks and incomplete downloads are isolated inside hidden staging folders.
   - Incomplete or unverified files are never written directly to destination folders.
3. **CyberShield 3-Stage Security Gate:**
   - **Stage 1 (Pre-Download):** Deceptive extension & double-extension trap screening (e.g., `.pdf.exe`, `.mp4.exe` auto-blocked).
   - **Stage 2 (Staging Containment):** Isolated execution during transfer.
   - **Stage 3 (Post-Download Gate):** Real PE heuristics + Microsoft-signed `MpCmdRun.exe -DisableRemediation` read-only evaluation.
     - `CRITICAL` (Trojan / Stealer / Ransomware) $\rightarrow$ Automatically moved to CyberShield's AES-256 Quarantine Vault.
     - `LOW` (Game cracks, emulators, PUPs) $\rightarrow$ Moved to destination with amber warning badge.
     - `CLEAN` $\rightarrow$ Moved to destination with clean completion badge.
4. **Native PySide6 Dark UI Shell:**
   - Linear & Fluent-inspired dark theme (`#0d0f17`).
   - Custom table delegates with real-time chunk progress bars.
   - Quick action toolbar (`+ New Download`, `⏸ Pause`, `▶ Resume`, `🗑 Delete`, `📂 Open Folder`).
   - Category filtering sidebar (`All`, `Downloading`, `Completed`, `Paused`, `Security Vault`).

---

## Project Structure

```text
C:\Users\Desktop\OmniFetch\
├── .agents/
│   └── mcp_config.json                # MCP configuration (context7)
├── .venv/                             # Isolated Python 3.12 virtual environment
├── app/
│   ├── main.py                        # Entry point
│   ├── ui/
│   │   ├── main_window.py             # Main application window
│   │   ├── download_table.py          # Table model & custom progress delegate
│   │   ├── add_dialog.py              # New download dialog with Stage 1 check
│   │   └── theme.py                   # Linear dark stylesheet (QSS)
│   ├── core/
│   │   ├── config.py                  # User configuration manager
│   │   ├── db.py                      # SQLite WAL database ledger
│   │   ├── staging.py                 # .staging containment & chunk assembly
│   │   ├── security_gate.py           # 3-Stage CyberShield Gate orchestrator
│   │   └── engine_manager.py          # Central engine & thread coordinator
│   ├── engines/
│   │   └── http/
│   │       ├── downloader.py          # Async multi-segment Range downloader
│   │       └── worker.py              # PySide6 background QThread
│   └── integrations/
│       ├── cybershield_cli.js         # Node.js CLI wrapper for CyberShield engines
│       └── cybershield_bridge.py      # Read-only Python bridge to CyberShield
├── tests/
│   ├── test_http_segments.py          # Range requests, multi-chunk, pause/resume
│   ├── test_staging_gate.py           # Staging assembly & 3-stage security gate
│   └── test_ui_components.py          # Models, delegates, and configuration
├── launch_omnifetch.bat               # Windows launcher
├── pytest.ini
└── requirements.txt
```

---

## Verification & Testing

To run the full automated verification test suite:

```powershell
cd File Path
.venv\Scripts\python.exe -m pytest -v
```
