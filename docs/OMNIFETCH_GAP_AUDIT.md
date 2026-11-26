# OmniFetch Engineering Forensic Audit & Feature Gap Report

**Audit Date:** 2026-11-25  
**Target Workspace:** `C:\Users\shrey\Desktop\OmniFetch` (strict read-only audit; zero application code or executable modified)  
**Dependency Guardrail:** `C:\Users\shrey\Desktop\CyberShield` remained strictly read-only throughout inspection.

---

## Executive Summary

While OmniFetch possesses a clean visual shell (`PySide6`), working BitTorrent metadata inspection (`UploadMode` + `default_dont_download`), working single/multi-segment HTTP range transfers on cooperative hosts, functional AES-128-CTR/CBC-MAC MEGA decryption primitives, and a real CyberShield CLI bridge, **cross-restart durability, link-expiry recovery, adversarial HTTP probe/header negotiation, concurrency queuing, per-task inspection UX, and failure-mode security hardening have critical production gaps**.

### Key Empirically Proven Findings
1. **Live Hetzner `100MB.bin` Failure (`FAILED (Server disconnected)`) Root Cause Proven:**  
   Live diagnostics using `OmniFetch\.venv` (`aiohttp 3.14.5`) and `curl.exe 8.23.0` (Schannel) against `https://fsn1-speed.hetzner.com/100MB.bin` proved that the origin server closes the TCP/TLS connection without an HTTP response (`ServerDisconnectedError` / `curl (56) server closed abruptly`) on **all `HEAD` requests** AND on **`GET` requests carrying `Mozilla/5.0 ...` or Python `aiohttp`/`urllib` User-Agents**, whereas **`GET` requests with client User-Agents (`curl/8.7.1`, `OmniFetch/1.0`) succeed immediately with `HTTP 206 Partial Content`** (`Content-Range: bytes 0-0/104857600`). Because `app/engines/http/downloader.py:44-48` hardcodes `Chrome/131.0.0.0` (`Mozilla/5.0...`) without UA fallback or non-Range fallback, every retry fails identically at 0 bytes.
2. **Cold-Restart Torrent Resume Is Structurally Broken on Two Layers:**  
   - `app/core/engine_manager.py:53,120` keeps `self.torrent_sources` only in RAM and stores `"torrent:{name}"` in SQLite `tasks.url` for magnet-resolved `lt.torrent_info` objects, never caching `.torrent` metadata files to disk.
   - `app/engines/torrent/session.py:216` saves `resume.dat` with `lt.save_resume_flags_t.only_if_modified` (omitting `save_info_dict`), while shutdown (`app/core/engine_manager.py:308-314` -> `app/engines/torrent/session.py:269-277`) issues asynchronous `save_resume_data()` **without** waiting for `save_resume_data_alert` or writing `write_resume_data_buf()`. Replaying the real user's `C:\Users\shrey\Downloads\OmniFetch\.staging\fcf44e99\resume.dat` (`Sintel`, 2,534 bytes) in a fresh `lt.session` proved `params.ti == None`, `params.trackers == []`, `has_metadata == False`, and `total_done == 0`.
3. **Live SQLite (`C:\Users\shrey\.omnifetch\omnifetch.db`) & Staging Forensics Confirm Multiple State-Machine Leaks:**  
   - Real `PAUSED` torrent rows (`fcf44e99` and `d67993b9`) persist stale `speed_bps` (`731957.0` and `208528.0`) and `eta_seconds` (`2` and `598`) because pause paths do not zero speed/ETA and `app/ui/download_table.py:110-114` renders them unmasked.
   - Row `d67993b9` shows `filename="Sintel"`, `resumable=-1` ("Checking") from pre-migration `ALTER TABLE` backfill (`app/core/db.py:60`), AND its `.staging\d67993b9\resume.dat` contains mismatched `name: b'test_folder'` (`info_hash: d984f67af9917b214cd8b6048ab5624c7df6a07a`) alongside `Sintel.mp4` (`129,241,752` bytes).
   - Over 45 orphaned UUID task staging folders remain under `C:\Users\shrey\Downloads\OmniFetch\.staging\`.
4. **Additional High-Severity Bugs Discovered:**  
   - **Tray Notification Crash:** `app/ui/main_window.py:729-753` calls `self.tray.notify(..., is_warning=True)`, raising `TypeError` against `OmniFetchTray.notify(self, title, message, level="INFO")` (`app/ui/tray.py:92`).  
   - **CyberShield Fail-Open & Stage 1 Bypass:** `app/integrations/cybershield_bridge.py:140-157` returns `verdict="ALLOW_CLEAN"` whenever `node.exe` fails or exits non-zero; `app/core/engine_manager.py:219-268` never checks `security_status == "CRITICAL"` before starting downloads received via Browser Bridge, Clipboard Grabber, or CLI.  
   - **Dead Config Knobs:** `max_concurrent_tasks` (`app/core/config.py:41`), `seeding_ratio_cutoff` (`app/core/config.py:48`), `ProxyDialog` entries (`app/ui/proxy_dialog.py:152-156`), and `query_threat_signatures_readonly()` (`app/integrations/cybershield_bridge.py:47`) are either unwired or never persisted/enforced at runtime.

---

## PHASE 1 — Reference Binary & Source Discovery (REA + Benchmark Grounding)

### 1.1 Physical Environment & Tooling Verification

A read-only recursive scan of `C:\Program Files`, `C:\Program Files (x86)`, `%LOCALAPPDATA%`, and `~\Desktop` confirmed **zero installed download managers** (`INSTALLED_REF_BINARIES: []`). All four reference artifacts reside physically in `C:\Users\shrey\Downloads\`. Notice also that `context7` MCP is not registered in this environment (and deep native disassemblers `ghidra`/`hopper`/`ida`/`kuna` are unconfigured locally in REA); therefore:
- **Physical artifacts** were analyzed directly using REA MCP (`open_binary`, `inspect_artifact`, `inspect_pe_imports`, `inspect_pe_resources`, `inspect_pe_certificates`) plus read-only Python binary/ZIP/JVM `.class` constant-pool & bytecode inspection.
- **Uninstalled runtime executables (`IDMan.exe`, `qbittorrent.exe`, `JDownloader2.exe`)** and `libtorrent 2.1.1` / `aiohttp 3.14.5` lifecycle APIs are explicitly benchmarked against **documented official architectures** (via web documentation search and direct `.venv` API introspection).

| Reference Target | Physical Path Verified | Size / SHA-256 | Artifact Format & Local Status | Verification Method Used |
| :--- | :--- | :--- | :--- | :--- |
| **IDM 6.43 Build 18** | `C:\Users\shrey\Downloads\idman643build18.exe` | 12,164,608 B<br>`7346128fab42957b4254eabdb012bfdbd751e9069361e98a6916f26bb03d62ee` | PE32 x86 installer signed by **Tonec Inc.** (`DigiCert Trusted G4 Code Signing`); custom unpacker stub + `PK\x03\x04` container at `0x4a1db7` (containing `components2/idmcch...`, browser ext files `background.js`, `content.js`, `welcome.html`, `captured.html`, no ZIP EOCD). `IDMan.exe` **not installed locally**. | REA (`inspect_pe_imports`, `inspect_pe_resources`, `inspect_pe_certificates`), raw PE stub/payload inspection + official IDM documented architecture |
| **qBittorrent 5.3.0 x64** | `C:\Users\shrey\Downloads\qbittorrent_5.3.0_x64_setup.exe` | 50,030,660 B<br>`aff5b3bdc00d6e5773d6099ba30f9696dd3dfd1669ab0f64ce5c4e7168486436` | Unsigned Nullsoft NSIS (`NullsoftInst` at `0x11c08`) PE32 setup wrapping x64 app payload (`163` installer Win32 imports across `ADVAPI32`, `SHELL32`, `USER32`, `KERNEL32`, etc.). `qbittorrent.exe` **not installed locally**. | REA (`open_binary`, `inspect_artifact`, `inspect_pe_imports`, `inspect_pe_certificates`), overlay marker check + official qBittorrent/libtorrent 2.1 specs & live `libtorrent 2.1.1.0` `.venv` API inspection |
| **MegaBasterd 8.61** | `C:\Users\shrey\Downloads\MegaBasterd_8.61.jar` | 81,955,655 B<br>`1693971148a5b5bd6e2a86d4e2e2f252fe0f7778b58d3a554302f5d4e3008a6e` | Executable Java JAR (ZIP container, 3,321 files / 279 dirs, 2,105 top-level `.class` files). Full unencrypted JVM bytecode directly inspectable locally. | REA (`open_binary`, `inspect_artifact`) + direct JVM `.class` constant-pool & opcode extraction on `com/tonikelope/megabasterd/*` |
| **JDownloader 2** | `C:\Users\shrey\Downloads\JDownloader2Setup_windows-amd64_v21_0_12_1.exe` | 76,154,440 B<br>`aa26656eb0b536411033a91ccd0a1fd0821207dc63890dc79ca904869783d430` | PE32+ x64 `install4j` installer (`install4j` at `0x7a159`, `311` PE imports across 6 DLLs via REA with `max_file_bytes=134217728`). `JDownloader2.exe` **not installed locally**. | REA (`inspect_pe_imports`), marker inspection + documented JDownloader 2 architecture |

---

### 1.2 Extracted Concrete Engineering Patterns by Benchmark Requirement

#### (a) Cold-Restart Persistence & Graceful Shutdown Flush
- **MegaBasterd 8.61 (`MegaBasterd_8.61.jar`, directly observed in bytecode):**
  - `SqliteSingleton.class` manages `~/.megabasterd8.61/megabasterd.db` via a synchronized JDBC wrapper (`_wrap(Connection)`) and exposes an explicit `shutdown()` path.
  - `DBTools.class` stores both durable download descriptors (`CREATE TABLE IF NOT EXISTS downloads(url TEXT, email TEXT, path TEXT, filename TEXT, filekey TEXT, filesize UNSIGNED BIG INT, filepass VARCHAR(64), filenoexpire VARCHAR(64), custom_chunks_dir TEXT, PRIMARY KEY ('url'), UNIQUE(path, filename))`) and persisted run ordering (`downloads_queue(url TEXT, PRIMARY KEY('url'))`).
  - `MainPanel.class`: `_byebye(ZZ)` checks `DownloadManager.getTransference_running_list()` / `getTransference_waitstart_queue()`, pauses active workers cleanly, shows `WarningExitMessage` until worker threads flush, and calls `byebyenow(ZZ)` -> `SqliteSingleton.getInstance().shutdown()` -> `DBTools.vaccum()` -> `System.exit(0)`. On cold boot, `resumeDownloads()` reads DB state + `.mctemp` / `/.MEGABASTERD_CHUNKS_<id>/` chunk directories and re-queues/resumes incomplete tasks without losing chunk progress.
- **qBittorrent / `libtorrent 2.1.1` (Not installed locally — benchmarked against documented official architecture & `.venv` `libtorrent 2.1.1.0` bindings):**
  - During shutdown, qBittorrent pauses the session (`ses.pause()`), iterates active handles calling `handle.save_resume_data(lt.save_resume_flags_t.flush_disk_cache | lt.save_resume_flags_t.save_info_dict)` (`save_info_dict = 2` confirmed in `libtorrent 2.1.1.0`), pumps `ses.wait_for_alert()` / `ses.pop_alerts()` until every outstanding `save_resume_data_alert` or `save_resume_data_failed_alert` arrives, and writes **both** `.fastresume` (`lt.write_resume_data_buf(alert.params)`) **and** cached `.torrent` metadata (`lt.write_torrent_file(alert.params)` / `lt.bencode(...)`) into `BT_backup/` (or SQLite `torrents.db`) before destroying `lt.session`. On cold start, all persisted torrents are re-added synchronously (paused handles remain paused via `lt.torrent_flags.paused` without `auto_managed`).
- **IDM / JDownloader 2 (Not installed locally — benchmarked against documented official architecture):**
  - **IDM** persists per-task metadata + byte-range boundaries + `ETag`/`Last-Modified` in `DwnlData/<task>/` segment control files before closing sockets on exit.
  - **JDownloader 2** serializes packages/links/offsets/headers atomically into rotated `cfg/downloadListXX.zip` archives with `.backup` recovery so abrupt kills fall back to the newest intact snapshot.

#### (b) Link/Token Expiration Detection & "Refresh Download Address" Recovery
- **MegaBasterd 8.61 (`Download.class` & `ChunkDownloader.class`, directly observed in bytecode):**
  - `ChunkDownloader.run()` explicitly branches on `SIPUSH 403` (temporary MEGA CDN URL expiration) and `SIPUSH 509` (bandwidth quota). Upon `403`, instead of failing permanently, `ChunkDownloader` invokes `Download.getDownloadUrlForWorker()`, which synchronizes on `_dl_url_lock`, calls `MegaAPI.getMegaFileDownloadUrl(url)` (`{"a":"g","g":"1","p|n":...}`) to fetch a fresh CDN URL `g`, updates `_last_download_url`, and retries the exact failing chunk offset seamlessly. It similarly validates on-disk `.chunk` sizes (`ChunkWriterManager`: `BAD chunk [id] on disk: size=X expected=Y -- deleting and waiting for re-download`) rather than trusting blind file presence.
- **IDM & JDownloader 2 (Not installed locally — documented official architecture):**
  - **IDM:** Persists server `ETag` and `Last-Modified`. Upon `401`/`403`/`410`/HTML-login redirect during resume, IDM surfaces **"Refresh Download Address"**, opens the captured `Referer` origin in the browser, waits for the user/extension to intercept the replacement URL, validates identity using HTTP **`If-Range`** (`ETag` / `Last-Modified`) or `Content-Length`, and resumes into the **existing** partial segment files without losing prior progress.
  - **JDownloader 2:** Separates container URL (`mega.nz`, `drive.google.com`, page origin) from ephemeral CDN download URL so expired CDN links trigger host-plugin regeneration or user-guided URL replacement.

#### (c) Duplicate Download Detection (`info_hash` / URL Normalization)
- **MegaBasterd 8.61 (`DBTools.class` & `Download.class`, directly observed in bytecode):**
  - Enforces SQLite `PRIMARY KEY ('url')` and `UNIQUE(path, filename)` (`DBTools.insertDownloadReturningName()`), rejecting duplicate queue entries (`' file is already downloading?'`) or auto-suffixing destination filenames safely on intentional collision (`_appendSuffix`).
- **qBittorrent (Not installed locally — documented official architecture):**
  - Deduplicates strictly by BitTorrent `info_hash` (`v1` SHA-1 / `v2` truncated SHA-256). Adding an already-present magnet or `.torrent` does **not** spawn a duplicate row; it merges new trackers/web-seeds into the existing handle or prompts the user.

#### (d) Multi-Segment Failure Recovery & Connection Pooling
- **MegaBasterd 8.61 (`Download.class`, `ChunkDownloader.class`, `MegaAPI.class`, directly observed in bytecode):**
  - Separates metadata provisioning (`DownloadManager._provision`), bounded queue admission (`TransferenceManager._max_running_trans` across `_transference_waitstart_queue` / `_transference_running_list`), per-worker exponential backoff (`MiscTools.getWaitTimeExpBackOff`), IP-aware 509 sleep/rotation (`sleepWithIpAwareBackoff`), and chunk verification (`ChunkInvalidException`).
- **`aiohttp 3.14.5` Lifecycle Spec (Verified in `.venv` & aiohttp official docs):**
  - Creating a fresh `aiohttp.TCPConnector` + `aiohttp.ClientSession` with `force_close=True` on every retry or probe is a documented anti-pattern: it forces full TCP 3-way + TLS 1.2/1.3 handshakes every attempt, prevents HTTP keep-alive reuse, exhausts ephemeral ports (`TIME_WAIT`), and prevents clean adaptive socket tuning. Standard practice shares a scoped `ClientSession` + `TCPConnector(limit=..., limit_per_host=..., ttl_dns_cache=300)` per task/engine lifecycle, using `force_close=True` only as fallback on broken keep-alive servers.

---

## PHASE 2 — Deep Forensic Audit of Current `OmniFetch` Codebase

### Scenario 1: Cold-Restart Torrent Resume Failure

**Scenario:** User adds `Sintel` magnet/torrent, pauses at 98%, clicks `Quit OmniFetch` from system tray, relaunches `OmniFetch.exe`, and clicks `Resume`.

1. **No magnet `.torrent` metadata persisted & `tasks.url` destroyed when `ti` passed:**
   - When adding via `AddDownloadDialog` -> `MainWindow._handle_torrent_add` (`app/ui/main_window.py:557-594`), `ti = self._fetch_magnet_metadata_nonblocking(url)` returns an in-memory `libtorrent.torrent_info` object and passes `source=ti` to `EngineManager.add_torrent_download()` (`app/ui/main_window.py:587`).
   - `app/core/engine_manager.py:120` checks `isinstance(source, str)`; because `source` is `lt.torrent_info`, SQLite `tasks.url` is overwritten with **`"torrent:Sintel"`**. The magnet URI, trackers, and `info_hash` are never saved to SQLite (`app/core/db.py:31-53` has no `info_hash`, `magnet_uri`, `torrent_path`, `file_priorities`, `sequential`, or `stop_ratio` columns).
   - `app/engines/torrent/session.py:43` creates `.staging/_metadata_cache`, and `fetch_magnet_metadata()` (`app/engines/torrent/session.py:93-146`) resolves `ti`, but **never writes `<info_hash>.torrent`** using `lt.write_torrent_file` / `lt.create_torrent`. Similarly, remote `.torrent` downloads overwrite one shared file `remote_fetched.torrent` (`app/ui/main_window.py:575`) rather than per-task `<info_hash>.torrent`.
2. **Shutdown flush does NOT wait for `save_resume_data_alert` or write `resume.dat`:**
   - Tray `Quit OmniFetch` (`app/ui/tray.py:62-64,89-90`) -> `MainWindow.force_quit()` -> `closeEvent()` (`app/ui/main_window.py:776-786`) -> `EngineManager.shutdown()` (`app/core/engine_manager.py:308-314`).
   - `EngineManager.pause_all()` (`app/core/engine_manager.py:298-300`) stops workers for **already-running** tasks (waiting up to 1.5s at `engine_manager.py:278`). However, if a torrent was already paused earlier or still running during shutdown, `EngineManager.shutdown()` finishes at line `313` by calling `self.torrent_session.flush_all_sessions()` (`app/engines/torrent/session.py:269-277`):
     ```python
     # app/engines/torrent/session.py:273-275
     handle.save_resume_data(lt.save_resume_flags_t.flush_disk_cache)
     handle.pause()
     ```
     **This never pumps `self.ses.pop_alerts()`, never waits for `save_resume_data_alert`, and never writes `lt.write_resume_data_buf()` to disk.** Immediately afterward, `self.db.close()` executes (`app/core/engine_manager.py:314`) and `app.exec()` exits (`app/main.py:113-115`), destroying `lt.session` before libtorrent finishes disk-cache flush or resume serialization.
3. **Even when paused interactively earlier, `resume.dat` omits `info_dict` (`save_info_dict`) and corrupts cold restart:**
   - `save_resume_data()` (`app/engines/torrent/session.py:216`) passes ONLY `lt.save_resume_flags_t.only_if_modified`, omitting `lt.save_resume_flags_t.save_info_dict` (`2`).
   - Direct forensic `lt.bdecode()` + fresh-`lt.session` replay of real `C:\Users\shrey\Downloads\OmniFetch\.staging\fcf44e99\resume.dat` (2,534 B) yielded:
     - `has info dict: False`, `trackers count: 0`, `params.ti: None`, `params.trackers: []`, `file_priority: [4]*11`.
     - Loading `params` into a new `lt.session` produced: **`has_metadata = False`, `state = downloading_metadata`, `total_done = 0`, `total_wanted = 0`, `trackers_on_handle = 0`** — even though 129.24 MB of `Sintel.mp4` already sits inside `.staging\fcf44e99\Sintel\`.
4. **On cold restart, `EngineManager` never restores handles, priorities, sequential mode, or seeding ratio:**
   - `EngineManager.__init__()` (`app/core/engine_manager.py:32-54`) never queries `self.db.get_all_tasks()` and never re-adds paused/incomplete torrents to `self.torrent_session`. `self.torrent_sources` (`line 53`) is empty `{}`.
   - Clicking `Resume` calls `MainWindow._resume_selected()` -> `EngineManager.resume_download(task_id)` (`app/core/engine_manager.py:288-296`):
     - `self.torrent_session.resume_torrent(task_id)` (`line 295`) is a **no-op** because `task_id` is absent from `self.active_handles`.
     - `start_download(task_id)` (`app/core/engine_manager.py:242-254`) finds `meta = {}`, falls back to `source = task["url"]` = `"torrent:Sintel"`, loses `priorities` (`None`), `sequential` (`False`), and `stop_ratio` (`0.0`).
     - If `resume.dat` is missing or unreadable, `add_active_torrent()` (`app/engines/torrent/session.py:170-192`) raises **`ValueError("Invalid torrent source")`**.
     - Even if `resume.dat` exists (like `fcf44e99`), `add_active_torrent()` enters `downloading_metadata` with 0 trackers (`total_done = 0`), while `TorrentDownloadWorker.run()` (`app/engines/torrent/worker.py:96-107`) overwrites SQLite `downloaded_bytes = 0` over the saved `127,778,679` bytes!
   - Also observed in `.staging\d67993b9\`: `resume.dat` belongs to `test_folder` (`info_hash: d984f67af9917b214cd8b6048ab5624c7df6a07a`) while `.staging\d67993b9\Sintel\Sintel.mp4` sits beside it — likely caused by `save_resume_data()` calling `self.ses.pop_alerts()` (`app/engines/torrent/session.py:219`) destructively in a shared alert queue without filtering/preserving unrelated task alerts.

---

### Scenario 2: Cold-Restart HTTP & MEGA Resume + 3-Day Link/Token Expiry

**Scenario:** User pauses HTTP or MEGA task at 98%, shuts down PC, relaunches 3 days later when signed URLs (`Expires=`, `X-Amz-Expires=`, Google `authuser`/cookie token, or MEGA `g` CDN URL) have expired, and clicks `Resume`.

1. **HTTP Persistence & `ETag` / `Last-Modified` / `Expires` Gaps:**
   - `app/core/db.py:31-53` stores only `url`, `total_bytes`, `downloaded_bytes`, `custom_headers`, `resumable`. There are **no columns** for `etag`, `last_modified`, `final_url`, `referer_origin` (distinct from download URL), or `expires_at` / token TTL parsing.
   - `HttpDownloader.probe()` (`app/engines/http/downloader.py:237-295`) and `_download_single_stream()` (`lines 464-466`) never extract `ETag`, `Last-Modified`, `Cache-Control`, or signed query expiry parameters.
   - `_download_segment()` (`app/engines/http/downloader.py:851-860`) and `_download_single_stream()` (`lines 433-440`) send `Range: bytes=...` **without `If-Range`**. If a refreshed or mutated asset returns `200 OK` instead of `206` during multi-segment resume, `_download_segment()` (`lines 872-895`) blindly **appends a full file (`200 OK`) onto `segment_N.part`**, silently corrupting the download! (Only single-stream checks `if downloaded_bytes > 0 and resp.status == 200` at `line 457`.)
2. **No Cold-Restart Rehydration & Stage-Skip Bug:**
   - `MainWindow.__init__()` / `EngineManager.__init__()` never transitions stale `"DOWNLOADING"` tasks from an unclean crash/reboot back to `"PAUSED"`, nor auto-restarts `"QUEUED"` tasks.
   - Worse, if single-stream `probe()` fails 3 days later (because the URL returns `403`/`410`), `download_task()` (`app/engines/http/downloader.py:344-380`) clears `accept_ranges = False` when `num_segments == 1` (`line 339`: `len(existing_segs) > 1` is `False` for paused single-stream because `save_segments` is only called AFTER EOF at `line 564`!), then falls into `_download_single_stream()` which hits `400 <= resp.status < 500` -> `NonRetryableHttpError` (`lines 441-443`) -> status `"FAILED"`.
3. **Zero "Refresh Download Address" Recovery Workflow:**
   - `MainWindow._show_context_menu()` (`app/ui/main_window.py:665-690`) offers only `Resume`, `Pause`, `Open Destination Folder`, `View Error Details`, and `Delete`. There is **no `Refresh Download Address` action**, no DB method to swap `tasks.url` / `custom_headers` while preserving `.staging/<task_id>/segment_*.part` and `segments`, and no URL-expiry detection categorizing `401`/`403`/`410` separately from permanent `404`.
4. **MEGA 3-Day Link Expiry & Folder Selective-Index Loss:**
   - **Single File (`app/engines/mega/worker.py:92-109, 201-271`):** Calls `client.get_file_info()` once (`line 92`) to obtain `download_url = file_data["g"]`, then passes that static string into `_stream_and_decrypt_file()`. If `download_url` expires mid-transfer (after proxy switch or resume delay) and MEGA returns `HTTP 403`:
     - `line 217-218` immediately raises `ConnectionError("Download stream error HTTP 403")`.
     - Because `ConnectionError` is **not** in `except (aiohttp.ClientError, asyncio.TimeoutError)` (`line 266`), the worker crashes (`FAILED`), **never re-calling `MegaAPI` `{"a": "g", "g": 1}`** to obtain a fresh CDN URL!
     - Note: Upon cold restart (clicking `Resume`), `MegaDownloadWorker` starts fresh and *does* re-call `get_file_info()` (`line 92`) and seeks to `(existing_size // 16) * 16` (`lines 190-194`), provided it is a single file. However, **`selected_file_indices` for MEGA folders is completely lost across pause/restart** because `engine_manager.py:255-264` omits `selected_file_indices`, and `db.py` never stores it — so resuming a selectively downloaded MEGA folder downloads **every unwanted file in the folder**. Additionally, `_download_folder()` (`mega/worker.py:169`) discards the boolean return value of `verify_file_mac(...)` instead of raising on MAC tamper!

---

### Scenario 3: Why `100MB.bin` Still Fails (`FAILED (Server disconnected)`)

**Live Failure Trace in `logs/omnifetch.log` (`lines 780-815`):**
- Task `9285171c`: `url=https://fsn1-speed.hetzner.com/100MB.bin`, `filename=100MB.bin`.
- `21:48:17`: `Pre-probing` (`app/engines/http/downloader.py:345`).
- `21:48:20`: `HEAD probe failed ...: Server disconnected` (`downloader.py:259`).
- `21:48:21`: `GET probe failed ...: Server disconnected` (`downloader.py:298`).
- `21:48:21`: Falls back to `_download_single_stream` (`total_bytes=0, accept_ranges=False`) (`downloader.py:379`).
- `21:48:22–21:48:36`: All 6 attempts (`RETRY_BACKOFF_SECONDS = [0.5, 1.0, 2.0, 4.0, 6.0]`, `downloader.py:39,425,536-543`) fail with `aiohttp.client_exceptions.ServerDisconnectedError: Server disconnected` at `0 bytes`, inside `aiohttp\streams.py:716` before HTTP status headers arrive (`_download_single_stream` lines `437-440`).

**Controlled Read-Only Matrix Reproduction (`aiohttp 3.14.5`, `certifi`, `curl.exe 8.23.0`):**

| Protocol / Address Family | User-Agent Sent | HTTP Method & Range | Result Observed |
| :--- | :--- | :--- | :--- |
| IPv4 (`78.46.170.2`) `aiohttp` | `Chrome/124` (`Mozilla/5.0...`) | `HEAD` | **`FAIL`: `ServerDisconnectedError`** |
| IPv4 `aiohttp` | `Chrome/124` (`Mozilla/5.0...`) | `GET` (`bytes=0-0` & no-Range) | **`FAIL`: `ServerDisconnectedError`** |
| IPv4 `aiohttp` | `Mozilla/5.0` / `Firefox/126` | `GET` (`bytes=0-0`) | **`FAIL`: `ServerDisconnectedError`** |
| IPv4 `aiohttp` | `Chrome/124` + `Sec-Fetch-*` | `GET` (`bytes=0-0`) | **`FAIL`: `ServerDisconnectedError`** |
| IPv6 (`2a01:4f8:0:a232::2`) `aiohttp` | `Chrome/124` (`Mozilla/5.0...`) | `GET` (`bytes=0-0`) | **`FAIL`: `ServerDisconnectedError`** |
| IPv4 `aiohttp` | *Empty dict* (`Python/3.12 aiohttp/3.14.5`) | `GET` (`bytes=0-0`) | **`FAIL`: `ServerDisconnectedError`** |
| Windows `curl.exe 8.23.0` (Schannel) | `curl/8.23.0` | `HEAD` (`-I`) | **`FAIL`: `curl: (56) server closed abruptly`** |
| Windows `curl.exe 8.23.0` (Schannel) | `Chrome/124` (`Mozilla/5.0...`) | `GET` (`--range 0-0`) | **`FAIL`: `curl: (56) server closed abruptly`** |
| Windows `curl.exe 8.23.0` (Schannel) | `curl/8.23.0` | `GET` (`--range 0-0`) | **`PASS`: `HTTP 206 Partial Content` (`0-0/104857600`)** |
| IPv4 & IPv6 `aiohttp` | **`curl/8.7.1`** | `GET` (`bytes=0-0`) | **`PASS`: `HTTP 206 Partial Content` (`104,857,600` B)** |
| IPv4 `aiohttp` | **`OmniFetch/1.0`** | `HEAD` | **`FAIL`: `ServerDisconnectedError`** |
| IPv4 `aiohttp` | **`OmniFetch/1.0`** | `GET` (`bytes=0-0`) | **`PASS`: `HTTP 206 Partial Content` (`0-0/104857600`)** |

**Exact Root Cause Diagnosis:**  
`fsn1-speed.hetzner.com` (`nginx`) enforces two server-side drop policies (closing TLS/TCP before sending an HTTP response — classic nginx `return 444` / TLS anti-bot rejection): (1) it drops **all `HEAD` requests**, and (2) it drops **`GET` requests whose `User-Agent` begins with `Mozilla/...` or Python default UAs**, while immediately serving **`HTTP 206 Partial Content`** to client identifiers such as `OmniFetch/1.0` or `curl/8.7.1`. Meanwhile, `app/engines/http/downloader.py:44-48,118,223,433,851` sends `DEFAULT_USER_AGENT = "Mozilla/5.0 ... Chrome/131.0.0.0 ..."` uniformly on every attempt with zero UA fallback/rotation (`OmniFetch/1.0`, `Wget`, stripped headers) on `ServerDisconnectedError`, and `download_task()` (`line 348-378`) ignores probe failures rather than adapting client profiles before retrying 6 times with identical headers. Furthermore, `_download_single_stream()` (`lines 437-439`) constructs a brand-new `TCPConnector(force_close=True)` and `ClientSession` on every retry attempt.

---

### Scenario 4: UI State-Machine Hygiene (`PAUSED` Speed/ETA, Duplicate `Sintel`, `Resumable` Mismatch)

Live inspection of `C:\Users\shrey\.omnifetch\omnifetch.db` (`?mode=ro`) revealed all three anomalies in real persisted rows:

1. **Stale Non-Zero `SPEED` and `ETA` While `PAUSED`:**
   - Live DB rows: `fcf44e99` has `status="PAUSED"`, `speed_bps=731957.0`, `eta_seconds=2`; `d67993b9` has `status="PAUSED"`, `speed_bps=208528.0`, `eta_seconds=598`.
   - **Code Root Causes:**
     - `TorrentDownloadWorker.run()` (`app/engines/torrent/worker.py:101-132`) writes `speed_bps` and `eta` in the polling loop; upon `!self.is_running`, lines `128-132` call `update_task_status(self.task_id, "PAUSED")` **without resetting `speed_bps=0.0, eta_seconds=0`**.
     - `MegaDownloadWorker._download_single_file()` / `_download_folder()` (`app/engines/mega/worker.py:111-114,146-149`) similarly sets `"PAUSED"` without clearing `speed_bps`/`eta_seconds` in SQLite.
     - `HttpDownloader._download_multi_segment()` (`app/engines/http/downloader.py:785-787`) pauses without zeroing `speed_bps`/`eta_seconds` in SQLite (only `_download_single_stream` clears them at `line 485`).
     - `DownloadTableModel.data()` (`app/ui/download_table.py:110-114`) unconditionally formats `speed_bps` and `eta_seconds` for display even when `status` is not `"DOWNLOADING"`, rather than enforcing `"--"` for `PAUSED`, `FAILED`, `QUEUED`, `COMPLETED`, `QUARANTINED`.
2. **Duplicate `Sintel` Rows Without `info_hash` / URL Deduplication:**
   - Live DB has two distinct tasks both titled `"Sintel"` with `url="torrent:Sintel"` (`d67993b9` and `fcf44e99`) and two separate 129 MB staging copies under `.staging\d67993b9` and `.staging\fcf44e99`.
   - **Code Root Cause:** `EngineManager.add_download()` (`app/core/engine_manager.py:80`), `add_torrent_download()` (`line 116`), and `add_mega_download()` (`line 166`) blindly mint `str(uuid.uuid4())[:8]` without checking SQLite for an existing matching `info_hash` or normalized `url`. (`app/core/db.py` lacks any uniqueness constraint or lookup helper on `info_hash` or `url`.)
3. **Why One `Sintel` Row Showed `Resumable: Yes` While the Other Showed `Checking`:**
   - Live DB shows `fcf44e99` (`created_at=1795623680`) has **`resumable=1`** (`"Yes"`), whereas earlier row `d67993b9` (`created_at=1795618002`) has **`resumable=-1`** (`"Checking"` in `app/ui/download_table.py:121`).
   - **Code Root Cause:** Older rows migrated by `ALTER TABLE tasks ADD COLUMN resumable INTEGER DEFAULT -1;` (`app/core/db.py:60`) received `resumable = -1`. Meanwhile, `TorrentDownloadWorker` (`app/engines/torrent/worker.py:51-132`) and `MegaDownloadWorker` (`app/engines/mega/worker.py:71-175`) **never call `self.db.update_task_resumable(self.task_id, 1)`** when running/pausing, and CLI/batch-grabber HTTP calls (`app/ui/main_window.py:414,769`) omit `resumable`, leaving any task initialized with `-1` stuck displaying `"Checking"` forever even while downloading or paused.

---

### Scenario 5: BitTorrent Completeness vs qBittorrent

- **Magnet Metadata & Pre-Download Gate (`COMPLETE` interactively; `HALF-COMPLETE` in Browser/Clipboard handoff):** `TorrentSessionManager.build_magnet_metadata_params()` (`app/engines/torrent/session.py:62-91`) uses modern `lt.parse_magnet_uri` + `upload_mode` + `default_dont_download` + `file_priorities = [0]*1000` + DHT/trackers, and `TorrentFileInspector` (`app/engines/torrent/file_tree.py:48-177`) smartly separates media traps from game installers. However, links handed off via Browser Bridge (`app/integrations/browser_bridge.py:117-119`) skip `TorrentDialog` completely and start raw `TorrentDownloadWorker` without pre-download inspection!
- **UPnP / NAT-PMP / PEX / Encryption Controls (`HALF-COMPLETE`):** `.venv` `libtorrent 2.1.1.0` defaults enable `enable_dht`, `enable_lsd`, `enable_upnp`, `enable_natpmp`, yet `app/engines/torrent/session.py:47-58` hardcodes minimal settings, exposes **zero** UI/config toggles for listen port, UPnP/NAT-PMP, PEX/LSD/DHT, encryption policy (`pe_settings`), or connection limits.
- **Selective File Priority & Sequential Persistence (`BROKEN` across restart):** `file_priorities` and `sequential` exist only in `EngineManager.torrent_sources[task_id]` RAM (`app/core/engine_manager.py:53,121-126`). Not persisted in SQLite.
- **Auto-Stop Seeding Cutoff (`BROKEN` config wiring):** `Config.seeding_ratio_cutoff` (`app/core/config.py:48`) is editable in `SettingsDialog` (`app/ui/settings_dialog.py:72-77`), yet `TorrentDialog` hardcodes `"stop_ratio": 0.0 if chk_auto_stop else 1.0` (`app/ui/torrent_dialog.py:239`), completely ignoring user settings!
- **Per-Task Torrent Detail Inspector (`MISSING`):** `MainWindow` (`app/ui/main_window.py:227-268`) only shows the 9-column table and `SpeedGraphWidget`. `TorrentDownloadWorker` computes `seeds`, `peers`, and `ratio` (`app/engines/torrent/worker.py:115-117`) and emits them in `progress_signal`, **but `EngineManager`/`MainWindow` ignores them completely (`app/ui/main_window.py:709-716`)**. There is no bottom drawer for **General / Files / Peers / Trackers / Chunks** (`handle.get_peer_info()`, `handle.trackers()`, `handle.file_progress()`).

---

### Scenario 6: IDM Completeness vs IDM

- **Max Concurrent Downloads Queue (`BROKEN` — Dead Setting):** `Config.max_concurrent_tasks = 4` (`app/core/config.py:41`) and `SettingsDialog.spin_concurrent` (1–10, `app/ui/settings_dialog.py:58-61`) are **never read or enforced in `EngineManager`**. `start_download()` (`app/core/engine_manager.py:219-268`) and `resume_all()` (`lines 302-306`) immediately launch an unlimited number of concurrent `QThread`s.
- **Global Speed Limiter (`HALF-COMPLETE`):** Works for HTTP (`TokenBucketRateLimiter`, `app/engines/http/downloader.py:68-102`) and libtorrent (`TorrentSessionManager.set_speed_limit`, `app/engines/torrent/session.py:259-267`), **but `MegaDownloadWorker` completely bypasses rate limiting** (`app/core/engine_manager.py:59-63`, `app/engines/mega/worker.py:224-233`).
- **Dynamic Segment Visualizer (`MISSING`):** Dynamic in-half splitting works in `HttpDownloader._download_multi_segment()` (`app/engines/http/downloader.py:649-687`) and writes to SQLite `segments`, yet there is **zero** per-segment live progress bar UI or connection slot viewer.
- **Scheduler, Post-Download Actions & Archive Extraction (`MISSING`):** Zero implementation in `config.py`, `main_window.py`, or `engine_manager.py` for download schedules, `Open File` on double-click (double-click only opens folder at `app/ui/main_window.py:651-663`), auto-shutdown/sleep, or auto-extract `.zip`/`.7z`/`.rar`.
- **Brave Extension Capture Reliability (`HALF-COMPLETE`):** `browser_extension/background.js:36-57,63-113` handles linked-image priority, multi-domain Google cookies, `referer`, and `userAgent`, **but** misses video/audio MIME stream sniffing (`webRequest` / media grabber), has no HTTP failure feedback back to Brave besides badge colors (`OK`/`AUTH`/`OFF`, `lines 140-147`), and extension popup/options token auto-pairing requires manual token copy (`app/ui/settings_dialog.py:105-115`). Furthermore, `autoIntercept` (`lines 226-236`) cancels Chrome's download **before** verifying OmniFetch accepted the `/api/handoff` POST (can lose the download if handoff fails!).

---

### Scenario 7: CyberShield 3-Stage Security Gate Durability

1. **Stage 1 Bypasses & Unwired Threat DB (`HALF-COMPLETE`):**
   - `add_download()` evaluates Stage 1 (`app/core/engine_manager.py:85-86`) and sets `security_status = "CRITICAL"`, yet `status` stays `"QUEUED"` and **`start_download()` (`lines 219-268`) NEVER blocks `security_status == "CRITICAL"`** — so Brave handoff (`app/integrations/browser_bridge.py:124-129`), Clipboard Grabber (`app/ui/main_window.py:414-419`), and CLI (`lines 769-773`) still download CRITICAL traps!
   - `add_mega_download()` (`app/core/engine_manager.py:165-204`) skips Stage 1 URL/filename checks altogether.
   - `CyberShieldBridge.query_threat_signatures_readonly()` (`app/integrations/cybershield_bridge.py:47-73`) reads CyberShield's `offline_engine.db` cleanly via `?mode=ro`, **but is never called anywhere in OmniFetch**.
2. **Cold Restart at 98% & `"STAGED"` / `"SCANNING"` Crash-Window Bug (`HALF-COMPLETE` / `BROKEN`):**
   - If paused/killed at 98% (`status="PAUSED"` / `"DOWNLOADING"`), HTTP multi-segment & Torrent/MEGA tasks *will* reach Stage 3 (`evaluate_post_download`) upon resuming and completing 100% — **provided** Stage 1/engine resume itself works (broken for Torrents/MEGA folders per Scenarios 1–2).
   - **CRITICAL CRASH WINDOW AT 100% (`"STAGED"` / `"SCANNING"`):** In `HttpDownloader._download_multi_segment()` (`app/engines/http/downloader.py:797-814`) and `_download_single_stream()` (`lines 567-584`), `StagingManager.assemble_segments()` (`app/core/staging.py:72-76`) **deletes all `segment_*.part` files immediately after assembling `.staging/<task_id>/<filename>`**, then sets status to `"SCANNING"`. If the process exits/crashes during Stage 3 MpCmdRun scanning, on cold restart `start_download()` re-runs `download_task()`:
     - For multi-segment: `segments` are all `"COMPLETED"`, so `assemble_segments()` raises **`FileNotFoundError: Missing segment at ...\segment_0.part`** (`app/core/staging.py:67`) even though the complete staged file sits in `.staging/<task_id>/<filename>`!
     - For single-stream: `part_path` is gone, so it **re-downloads the entire file from byte 0** and wastes bandwidth!
3. **Stage 3 Fail-Open Vulnerability (`CRITICAL BUG`):**
   - `CyberShieldBridge.scan_file()` (`app/integrations/cybershield_bridge.py:140-157`) returns **`verdict: "ALLOW_CLEAN", severity: "CLEAN"`** on non-zero `node.exe` exit code or exception (`timeout=45s`, missing `node.exe`, broken path)! Thus large downloads hitting the 45s timeout or frozen deployments lacking Node.js silently graduate to `Downloads\OmniFetch` badged **`"🛡️ Clean"`**!
   - Additionally, `quarantine_file()` (`app/integrations/cybershield_bridge.py:168`) passes raw `threat_name` to `subprocess.run`; if `threat_name` is `None`, Windows Python raises `TypeError` before CyberShield's quarantine CLI ever runs.
   - Bonus bug: Whenever Stage 3 produces `LOW`/`WARNING` or `QUARANTINED` (or any download fails), `MainWindow._on_task_completed` / `_on_task_failed` (`app/ui/main_window.py:729-753`) calls `self.tray.notify(..., is_warning=True)`, raising **`TypeError`** (`app/ui/tray.py:92` defines `level="INFO"`, not `is_warning`).

---

## PHASE 3 — Structured Gap Comparison Matrix

| Feature / Subsystem | Reference Standard (IDM / qBit / MegaBasterd) | Current OmniFetch Status (COMPLETE / HALF-COMPLETE / BROKEN / MISSING) | Exact Evidence (file:line & Root Cause) | Priority (P0 / P1 / P2 / P3) | Importance & User Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **HTTP Engine: Multi-Segment Range & In-Half Split** | IDM dynamic bisecting segmentation writing to isolated temp parts & joining in byte order | **COMPLETE** (when probe succeeds) | `app/engines/http/downloader.py:595-824`, `app/core/staging.py:41-78`; splits remaining largest active segment dynamically (`lines 649-687`) and stitches in `start_byte` order (`staging.py:53`). | P2 | Core speed accelerator; already reliable when initial probe gets `206` & `Content-Length`. |
| **HTTP Engine: Probe, UA Fallback & `ServerDisconnectedError`** | Multi-profile fallback (`HEAD` -> `GET Range` -> `GET` without Range; non-browser UA fallback on drop/403) | **BROKEN** | `app/engines/http/downloader.py:44-48,237-307,344-380,433-443`; hardcodes `Chrome/131` UA causing `fsn1-speed.hetzner.com/100MB.bin` nginx-444 drops (`logs/omnifetch.log:780-815`); `probe()` error ignored by `download_task()`. | **P0** | Direct popular mirrors/speedtests (Hetzner) permanently fail at `0 B` instead of downloading at full speed. |
| **HTTP Engine: Session / Connector Pooling** | Scoped persistent `ClientSession` + `TCPConnector(limit_per_host=..., ttl_dns_cache=300)` per task/app | **HALF-COMPLETE** | `app/engines/http/downloader.py:226,437,690`; `_download_multi_segment` pools inside task, but `_download_single_stream` (`line 437`) recreates `TCPConnector(force_close=True)` & `ClientSession` every retry attempt. | P1 | Redundant TLS handshakes, slow recovery, socket `TIME_WAIT` churn under drops. |
| **HTTP Engine: `ETag` / `Last-Modified` / `If-Range` Safety** | Store `ETag`/`Last-Modified`; send `If-Range` on resume; abort/reset on server mutation | **MISSING** | `app/core/db.py:31-53` lacks columns; `app/engines/http/downloader.py:239-294,851-895` ignores `ETag`/`Last-Modified`; `_download_segment` appends `200 OK` response onto `.part` (`lines 866-895`). | **P1** | Prevents silent file corruption when resuming multi-segment downloads if remote content changed. |
| **HTTP Engine: URL/Token Expiry & "Refresh Download Address"** | Detect `401`/`403`/`410`/HTML interstitials, retain partial `.part` bytes, swap URL + headers via browser capture | **MISSING** | `app/engines/http/downloader.py:441,861` treats all `4xx` as terminal `NonRetryableHttpError`; `app/ui/main_window.py:665-690` has no "Refresh Download Address" menu or `db.py` URL replacement flow. | **P1** | Eliminates losing 98% of a multi-GB cloud/Google Drive/S3 download when signed tokens expire. |
| **HTTP Engine: Global Speed Cap & Concurrency Queue** | Token bucket + bounded active-task FIFO queue enforcing `max_concurrent_tasks` | **BROKEN** | `app/core/config.py:41` (`max_concurrent_tasks=4`) & `app/ui/settings_dialog.py:58-61` exist in UI/config, **zero callers** in `app/core/engine_manager.py:219-306`; `HttpDownloader.rate_limiter` works (`downloader.py:68-102`). | **P1** | Queuing 50 links spawns 50 simultaneous QThreads, saturating disk I/O and network sockets. |
| **BitTorrent: Zero-Payload Magnet Metadata Inspection** | `upload_mode` + `default_dont_download` + 0 priorities + DHT/trackers (qBittorrent pattern) | **COMPLETE** (interactive dialog)<br>**HALF-COMPLETE** (extension/clipboard) | `app/engines/torrent/session.py:62-146` & `app/ui/main_window.py:478-595`; works cleanly via `AddDownloadDialog`. However, `app/integrations/browser_bridge.py:117-119` starts magnets directly, skipping `TorrentDialog`. | **P1** | Browser-clicked magnets skip Stage 1 pre-download trap unchecking and file tree selection. |
| **BitTorrent: `.torrent` Caching & Shutdown `save_resume_data` Flush** | Synchronous alert pump during shutdown (`save_info_dict`), write both `.fastresume` & `<ih>.torrent` | **BROKEN** | `app/core/engine_manager.py:120,308-314`; `app/engines/torrent/session.py:216,269-277`; omits `save_info_dict`, discards alerts on shutdown, never caches `.torrent`, overwrites `tasks.url` with `"torrent:{name}"`. | **P0** | Cold-restarting paused torrents loses metadata, file priorities, and progress (`total_done=0` / `Invalid torrent source`). |
| **BitTorrent: Cold-Restart Handle & Priority/Ratio Rehydration** | Auto-load persisted torrents on startup into `lt.session` preserving paused flag, priorities, sequential, ratio | **BROKEN** | `app/core/engine_manager.py:32-54,242-254`; `self.torrent_sources` is volatile RAM; `db.py` has no `file_priorities`/`sequential`/`stop_ratio`; `TorrentDialog` (`app/ui/torrent_dialog.py:239`) ignores `config.seeding_ratio_cutoff`. | **P0** | Paused/incomplete torrents cannot cleanly resume with user selections or seeding settings after reboot. |
| **BitTorrent: Peers, Trackers, Chunks & UPnP/NAT-PMP Controls** | Live peer/tracker/piece tabs + port/UPnP/encryption/DHT/PEX controls | **MISSING** | `app/engines/torrent/worker.py:109-118` emits `seeds`/`peers`/`ratio`, ignored in `app/ui/main_window.py:709-716`; `app/engines/torrent/session.py:47-58` hardcodes session settings without UI controls. | P1 / P2 | Users have zero visibility into stalled torrents, dead trackers, swarm health, or port forwarding. |
| **MEGA.nz: Exact Crypto, Folder Tree & 16B Alignment** | AES-128-CTR aligned offset, CBC zero-IV attr, block-ECB folder node keys, CBC-MAC verification | **COMPLETE** (single file)<br>**HALF-COMPLETE** (folder MAC & Stage 1) | `app/engines/mega/crypto.py:44-120` & `app/engines/mega/client.py:54-185` verified; `mega/worker.py:169` ignores `verify_file_mac()` boolean return in folders. | **P1** | Core decryption is solid; folder integrity mismatch is silently ignored without raising error. |
| **MEGA.nz: Mid-Stream Expired Temp-URL Auto-Refresh (`403`)** | On CDN `403`, call `MegaAPI.getMegaFileDownloadUrl()` under lock & retry current offset (`MegaBasterd`) | **MISSING** | `app/engines/mega/worker.py:92,151,217-218,266`; fetches `download_url` once before streaming loop; HTTP `403` raises non-retried `ConnectionError` and marks task `FAILED`. | **P0** | Long MEGA transfers or proxy-rotated chunks fail permanently when MEGA CDN URLs expire. |
| **MEGA.nz: Selective Folder Persistence, Bandwidth Cap & Proxy Save** | Persist selected node indices + proxies in DB/config; enforce global speed limit (`ThrottledInputStream`) | **BROKEN** | `app/core/engine_manager.py:59-63,255-264` drops `selected_file_indices` on resume and skips rate limiter; `app/ui/proxy_dialog.py:152-156` never writes proxies to `config.json` or DB. | **P1** | Resuming paused MEGA folders downloads unchecked files; speed cap & saved proxy list disappear. |
| **Persistence: Cold-Restart Task State Reconciliation & SQLite Locking** | Reconcile `DOWNLOADING` -> `PAUSED` on crash boot, recover `STAGED`/`SCANNING`, lock cross-thread writes | **BROKEN** | `app/main.py:76-82` & `app/core/engine_manager.py:32-54` do zero startup recovery; `app/core/db.py:19` shares `sqlite3.Connection(check_same_thread=False)` across QThreads & aiohttp server without a `threading.Lock`. | **P0** | Crashed tasks remain mislabeled `DOWNLOADING`, `"STAGED"` fails with `Missing segment_0.part`, and concurrent DB writes race. |
| **Persistence: Deduplication (`info_hash` & URL) + Staging Cleanup** | Deduplicate by `info_hash`/canonical URL (`PRIMARY KEY`/`UNIQUE`), GC orphaned staging dirs | **MISSING** | `app/core/engine_manager.py:80,116,166` generates random UUIDs; live DB holds two `"Sintel"` rows; `Downloads\OmniFetch\.staging` has 45+ orphan directories. | **P0** | Clutters UI with duplicate downloads and leaks gigabytes of orphan `.staging` folders on disk. |
| **Browser Extension & Clipboard Grabber** | Auth handoff, cookie/referer forward, verified handoff before browser cancel, media sniffer, Stage 1 parity | **HALF-COMPLETE** | `browser_extension/background.js:151-240` cancels Chrome download (`line 228`) **before** `handoffLink` succeeds (`line 236`); `clipboard_listener.py:19-40` only grabs known static extensions & doesn't deduplicate vs DB. | P1 / P2 | Failed bridge POST after browser cancel silently drops user downloads; dynamic stream URLs aren't sniffed. |
| **Desktop UI/UX: Live Table State Hygiene & Tray Notification** | Zero speed/ETA when stopped; clean model updates; working tray alerts; bottom inspector drawer | **HALF-COMPLETE** (table/tray broken)<br>**MISSING** (bottom drawer) | `app/ui/download_table.py:110-114` displays frozen `Speed`/`ETA` on `PAUSED` tasks; `app/ui/main_window.py:729-753` calls `tray.notify(..., is_warning=True)` -> `TypeError` against `tray.py:92`; zero inspector pane in `main_window.py:263-269`. | **P0** (hygiene & tray)<br>**P1** (drawer) | Misleading UI telemetry, broken alert toasts on errors/threats, and blind debugging without segment/peer tabs. |
| **CyberShield Gate: Stage 1–3 Fail-Closed & Quarantine Safety** | Strict Stage 1 block across all entrypoints; Stage 3 fail-closed on missing/failed engine; safe crash recovery | **HALF-COMPLETE** (fail-open & Stage 1 bypass) | `app/integrations/cybershield_bridge.py:140-168` returns `ALLOW_CLEAN` on CLI errors & passes `None` `threat_name`; `app/core/engine_manager.py:219-268` runs Stage 1 `CRITICAL` tasks; `query_threat_signatures_readonly()` unused. | **P0** | Compromises core security promise: blocked browser links still download, and failed Stage 3 scans report `"Clean"`. |
| **Power Features: Scheduler, Post-Download Actions, Auto-Extract** | Scheduled start/stop queues, open file / PC shutdown / archive extraction on finish | **MISSING** | Absent from `app/core/config.py`, `app/core/engine_manager.py`, `app/ui/main_window.py`, `app/ui/settings_dialog.py`. | **P2** | Quality-of-life gap compared to mature IDM/qBittorrent/JDownloader suites. |

---

## PHASE 4 — Prioritized Execution Blueprint (DO NOT EXECUTE YET)

> [!CAUTION]
> **Implementation Hold:** Per audit protocol, zero code edits have been made. Review and approve Sprint 1 before beginning implementation.

### Sprint 1 — P0 Critical Reliability (Must Fix First)

1. **SQLite Schema Expansion & Thread-Safe Locking (`app/core/db.py`, `app/core/staging.py`):**
   - Wrap all SQLite transactions in `Database` with a re-entrant `threading.RLock()`.
   - Add additive migrations on `tasks`: `info_hash TEXT`, `torrent_path TEXT`, `file_priorities TEXT`, `sequential INTEGER DEFAULT 0`, `stop_ratio REAL`, `selected_indices TEXT`, `etag TEXT`, `last_modified TEXT`, `final_url TEXT`, `origin_referer TEXT`, `expires_at REAL`.
   - Enforce `info_hash` / canonical-URL deduplication helpers (`find_duplicate_task(url, info_hash)`) across `add_download`, `add_torrent_download`, and `add_mega_download` (with user prompt to Merge Trackers / Skip / Auto-Suffix).

2. **Bulletproof BitTorrent Metadata Caching, Shutdown Flush & Cold-Restart Rehydration (`app/engines/torrent/session.py`, `app/engines/torrent/worker.py`, `app/core/engine_manager.py`, `app/main.py`):**
   - Whenever `fetch_magnet_metadata()` or `.torrent` open resolves `lt.torrent_info`, persist `<info_hash>.torrent` immediately inside `.staging/<task_id>/meta.torrent` (and `_metadata_cache/<info_hash>.torrent`), storing both `info_hash` and `torrent_path` in SQLite instead of `"torrent:{name}"`.
   - Call `handle.save_resume_data(lt.save_resume_flags_t.flush_disk_cache | lt.save_resume_flags_t.save_info_dict)` (and `lt.save_resume_flags_t.only_if_modified | lt.save_resume_flags_t.save_info_dict` periodically during runtime).
   - **Demultiplex session alerts cleanly:** Maintain a central session alert pump (or route all alerts into per-`info_hash` / `handle` handlers instead of destructively calling `pop_alerts()` per task, eliminating the cross-task `resume.dat` contamination seen in `d67993b9`).
   - Make `TorrentSessionManager.flush_all_sessions(timeout=4.0)` synchronously iterate all active handles, trigger `save_resume_data`, and wait on `wait_for_alert` / `pop_alerts` until all handles confirm `save_resume_data_alert` / `save_resume_data_failed_alert` (writing both `resume.dat` and cached `meta.torrent`), **before** `db.close()`.
   - Add `EngineManager.recover_on_startup()`: reconcile interrupted `"DOWNLOADING"`/`"QUEUED"` -> `"PAUSED"` (unless auto-resume enabled), restore paused torrent handles into `lt.session` with `paused` flag + saved `file_priorities` + `sequential`, and directly resume `"STAGED"`/`"SCANNING"` tasks straight to Stage 3 scan on the assembled file without calling `assemble_segments()` or wiping partial files.

3. **Fix `100MB.bin` `ServerDisconnectedError` & Adaptive HTTP Probing (`app/engines/http/downloader.py`):**
   - Implement tiered probe & transfer header strategy on `ServerDisconnectedError`, `ClientResponseError(403/406/416)`:
     1. Primary browser profile (`Chrome/131` + Referer/Cookie if from browser).
     2. Fallback **non-browser client profile** (`User-Agent: OmniFetch/1.0`, matching our verified `HTTP 206` result on `fsn1-speed.hetzner.com/100MB.bin`) if `HEAD` or `GET Range: bytes=0-0` disconnects at 0 bytes (`ServerDisconnectedError`) or returns `403`/`406`.
     3. Fallback full `GET` without `Range` header if `Range: bytes=0-0` is rejected.
   - Persist chosen working header profile (`custom_headers` / `effective_user_agent`) to the task so `_download_single_stream` / `_download_multi_segment` reuse the profile that passed probing.
   - Reuse one scoped `ClientSession` + `TCPConnector` across retry attempts inside `_download_single_stream()`.

4. **Automatic MEGA Temp-URL (`403`) Refresh (`app/engines/mega/worker.py`, `app/engines/mega/client.py`):**
   - Inside `_stream_and_decrypt_file()`, catch `resp.status == 403` (expired MEGA CDN `g` URL) and invoke a callback/client refresh (`get_file_info` / `get_folder_file_download_url`) up to N retries, resuming cleanly from `(current_offset // 16) * 16`.
   - Enforce `verify_file_mac()` failure raising `ValueError` in `_download_folder()` as well as `_download_single_file()`.

5. **UI State Hygiene, Tray Fix & CyberShield Fail-Closed (`app/ui/download_table.py`, `app/ui/main_window.py`, `app/integrations/cybershield_bridge.py`, `app/core/engine_manager.py`):**
   - Zero `speed_bps=0.0, eta_seconds=0` in SQLite on every pause/fail transition across all three engines, AND mask columns 3–4 to `"--"` in `DownloadTableModel.data()` whenever `status != "DOWNLOADING"`.
   - Ensure `TorrentDownloadWorker` and `MegaDownloadWorker` call `db.update_task_resumable(task_id, 1)` on start/load; backfill migrated rows cleanly.
   - Fix `self.tray.notify(..., level="CRITICAL" / "WARNING")` in `app/ui/main_window.py:729-753` (removing invalid `is_warning=True`).
   - Change `CyberShieldBridge.scan_file()` to **fail-closed** (`verdict="SCAN_ERROR"` / hold in staging or retry/warn cleanly rather than `"ALLOW_CLEAN"`), sanitize `str(threat_name or "Unknown")` in `quarantine_file()`, and enforce `security_status != "CRITICAL"` in `EngineManager.start_download()`.

---

### Sprint 2 — P1 Core Parity (IDM / qBittorrent / MegaBasterd Essentials)

1. **IDM-Style `ETag` / `If-Range` & "Refresh Download Address":**
   - Persist `ETag`, `Last-Modified`, `final_url`, `origin_referer`, and parsed token `expires_at`. Send `If-Range` when resuming partial segments; abort/prompt on mismatch instead of appending mismatched `200 OK` payloads in `_download_segment()`.
   - Add `"Refresh Download Address"` context-menu action + dialog (accepting pasted URL or opening `origin_referer` in Brave for `/api/handoff?replace_task_id=<id>`), updating `tasks.url` + `custom_headers` while preserving `.staging/<task_id>/segment_*.part`.
2. **Real Queue Concurrency Scheduler & Rate Limiting Parity:**
   - Implement a centralized admission queue in `EngineManager` strictly honoring `config.max_concurrent_tasks` (holding overflow tasks in `"QUEUED"` and auto-promoting next queued task on completion/pause/failure).
   - Share `TokenBucketRateLimiter` with `MegaDownloadWorker` (`CHUNK_READ_SIZE` loop) and persist `ProxyPool` entries + `passive_mode` in `~/.omnifetch/config.json` or SQLite.
   - Persist MEGA `selected_indices` in SQLite and pass it inside `start_download()`, and wire `config.seeding_ratio_cutoff` into `TorrentDialog` defaults and `TorrentDownloadWorker`.
3. **Bottom Per-Task Inspector Drawer (`MainWindow`):**
   - Replace static layout below `QTableView` with a collapsible tabbed inspector (`General` | `Chunks / Segments` | `Files` | `Peers & Trackers` | `Security Log`) bound to currently selected task (`handle.get_peer_info()`, `handle.trackers()`, live `segments` table, `security_audit` rows).
4. **Stage 1 Browser/Clipboard Parity & Safe Interception:**
   - Route browser-handed `magnet:` links through non-blocking metadata inspection + `TorrentFileInspector` before payload download; verify `/api/handoff` succeeds in `browser_extension/background.js` *before* calling `chrome.downloads.cancel()`. Call `query_threat_signatures_readonly()` during Stage 1 URL/domain checks.

---

### Sprint 3 — P2 Power Features & Polish

1. **Orphan Staging Garbage Collector:** Startup/periodic cleanup of `.staging/<id>` directories whose `id` no longer exists in `tasks` and isn't `_metadata_cache`.
2. **BitTorrent Session Controls:** Expose listen port, DHT/PEX/LSD, UPnP/NAT-PMP, encryption mode, and active connection limits in `SettingsDialog` (`TorrentSessionManager.apply_settings`).
3. **Post-Download Automation & Scheduler:** Start/stop queue windows, double-click `Open File` vs `Open Folder`, post-completion `Shutdown/Sleep/Launch`, and safe archive auto-extraction (only *after* Stage 3 CyberShield `CLEAN` verdict!).
4. **Brave Extension Sniffer:** Dynamic media stream detection (`video/*`, `audio/*`, HLS/MP4 CDN capture) + one-click localhost token pairing.

---

### Real Non-Mocked Integration Test Plan (Required Gate for Sprint 1 Sign-Off)

Current `tests/test_*.py` tests execute purely in-process (same `Database`, same `EngineManager`, local loopback HTTP handlers, or mocked/unit inputs), which is why zero tests caught cold-restart data loss, alert demultiplexing corruption, or Hetzner UA drops. Sprint 1 must pass these **non-mocked end-to-end integration tests**:

1. **Test 1 — Real Cold-Restart BitTorrent (Magnet Metadata + Selective Files + Progress Continuity):**
   - *Setup:* Seed a multi-file fixture torrent from a real second local `libtorrent.session` seeding on loopback/DHT disabled with tracker/peer loopback; fetch metadata in Session A (`TorrentSessionManager` instance #1), deselect file 1 (`priority=0`), download >50% of file 0, pause task, call `EngineManager.shutdown()` cleanly, destroy `EngineManager` and `lt.session`, and close SQLite.
   - *Cold Restart:* Instantiate brand-new `Database`, `EngineManager`, and `TorrentSessionManager` instance #2 pointing at the same DB & `.staging`. Assert: (a) UI/DB shows `PAUSED`, `speed_bps == 0.0`, `eta_seconds == 0`, `resumable == 1`; (b) `.torrent` metadata and `resume.dat` (with `save_info_dict`) reload without `Invalid torrent source` or resetting `downloaded_bytes = 0`; (c) clicking `Resume` finishes file 0 to 100%, skips deselected file 1, enforces `stop_ratio`, and runs Stage 3 scan cleanly.
2. **Test 2 — Real Cold-Restart Multi-Segment HTTP + Crash Recovery at `"STAGED"`/`"SCANNING"`:**
   - Start a local real HTTP `Range` server supporting `ETag` and `Last-Modified`; download ~60% of a 4 MB binary across 8 segments, shut down `EngineManager` + `Database`, instantiate fresh `Database` + `EngineManager`, resume to 100%, verify byte-for-byte SHA-256 match and clean `ETag` mismatch handling (`If-Range` returning `200 OK` restarts safely without appending corruption). Also simulate crash at `status="STAGED"` (`.part` files already removed) and prove cold-restart finishes Stage 3 scan instead of throwing `Missing segment_0.part`.
3. **Test 3 — Real Cold-Restart Selective MEGA Folder & Expired Temp-URL (`403`) Auto-Refresh:**
   - Spin up a local mock MEGA API `/cs` + CDN HTTP server serving encrypted AES-128-CTR chunks and valid CBC-MACs: return `HTTP 403` on chunk request #3, verify `MegaDownloadWorker` calls `/cs` `{"a":"g","g":1}`, obtains URL v2, completes from aligned offset without failing; also pause a selective 1-of-3 file folder transfer, destroy `EngineManager`/`Database`, cold-restart, resume, and prove only the selected file is downloaded and verified clean.
4. **Test 4 — Hetzner-Style Strict Server Simulation (`HEAD` + `Mozilla/5.0` Abrupt TCP Close) & Live Network Smoke:**
   - Run an asyncio raw TLS/TCP server replicating `fsn1-speed.hetzner.com`: forcibly `transport.close()` (EOF with zero HTTP bytes) whenever method is `HEAD` OR `User-Agent` starts with `Mozilla/` or `Python/`, while serving `206 Partial Content` + `Content-Range` for `User-Agent: OmniFetch/1.0`. Assert `HttpDownloader.probe()` + `download_task()` auto-adapts to `OmniFetch/1.0` and downloads 100% across multiple segments cleanly. Run optional online smoke against `https://fsn1-speed.hetzner.com/100MB.bin` (`probe()` returning `total_bytes == 104857600, accept_ranges == True`).
5. **Test 5 — CyberShield Fail-Closed, Stage 1 Gate & Tray Notification Integration:**
   - Point `CyberShieldBridge.node_exe` to a nonexistent binary / crashing script and invoke `evaluate_post_download()` inside `SecurityGate`; prove it **never** emits `ALLOW_CLEAN` and holds the file in `.staging/`. Submit a Stage-1-blocked double extension (`invoice.pdf.exe`) via `/api/handoff` and verify `EngineManager.start_download()` refuses to start it. Trigger `_on_task_completed` with `LOW`/`CRITICAL` verdicts and `_on_task_failed` against `OmniFetchTray.notify()` without `TypeError`.
