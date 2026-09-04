# Browser Cache Forensics Tool

**A real, no-mock-data digital forensics tool that parses Chrome/Chromium's Simple Cache disk-cache format byte-for-byte — CLI + Web App.**
Recovers cached URLs, cleartext-cookie evidence, credentials embedded in cached URLs, cached executable downloads, CRC32 integrity anomalies, and double-keyed (partitioned) cache markers by real-parsing the actual `SimpleFileHeader` and `SimpleFileEOF` binary structures of real cache entry files on disk — no simulated or sample data, ever.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ Disclaimer (read before use)

This software is provided **strictly for educational, defensive-security, and digital-forensics learning purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Run this tool **only** against browser profiles, cache directories, or individual cache entry files that you own or for which you have explicit, documented authorization to examine. Examining another person's or organization's data without authorization may violate computer-crime, privacy, or wiretapping laws (e.g. the Computer Fraud and Abuse Act, GDPR, or equivalent legislation in your jurisdiction) and organizational policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including data loss, privacy violations, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a substitute for certified forensic tooling.** This tool is **not** a substitute for certified, court-admissible forensic software (e.g. EnCase, Axiom, X-Ways), a documented chain-of-custody process, or expert testimony from a qualified digital forensics examiner. It does not preserve evidence integrity (hashing, write-blocking, imaging) on your behalf — you are responsible for that if the results matter forensically.
- **Best-effort header extraction, not a full deserializer.** Chromium's cached-response-stream format embeds HTTP headers inside an internal, largely undocumented "Pickle" structure. This tool does **not** implement a full Pickle deserializer. Instead it does a documented, best-effort regular-expression scan of the raw stream bytes (decoded leniently as latin-1) for recognizable header-line substrings (`Content-Type:`, `Set-Cookie:`, `Location:`, `Cache-Control:`). This can produce false negatives (a header present but not matched) and, rarely, false positives (a byte sequence that coincidentally looks like a header). Treat extracted headers as investigative leads, not ground truth — verify anything forensically significant with a dedicated Chromium cache parser or the Chromium source itself.
- **Simple Cache only.** This tool targets Chromium's modern **Simple Cache** backend specifically (the default on Windows/macOS/Linux/Android for recent Chrome/Chromium/Edge/Brave). It does **not** parse the older `blockfile` cache backend (`data_0`..`data_3`, `index` files) used by some older profiles/platforms — those files will simply not match the Simple Cache naming convention or magic number and will be skipped or flagged as unrecognized.
- **No guaranteed detection.** Absence of findings does **not** mean a cache is free of sensitive artifacts. This tool checks a specific, limited set of forensically-relevant patterns only.
- **Read-only by design.** The Security Engine only opens cache entry files for reading — it never modifies, deletes, or writes back to any file it parses. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything important.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to examine a given browser profile or cache, **do not run this tool against it.**

---

## Who should use this project

- Digital forensics investigators and incident responders who need a fast, transparent first pass over a suspect's or endpoint's browser cache.
- DFIR students and self-learners studying Chromium's on-disk artifact formats.
- Security engineers triaging a compromised or suspicious workstation who want to know what was cached (and how) without exporting to a full commercial forensic suite.
- Anyone auditing their own machine's browser cache for accidentally-cached secrets (credentials in URLs, cookies over plaintext HTTP).

## Why use this project

- **Real binary parsing only** — every result comes from actually reading and `struct`-unpacking a real cache entry file's real bytes on the current machine, including a real `zlib.crc32` computation over the real extracted stream. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py` operating on plain dicts. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI/scripting) and the web app (for dashboards/case tracking) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a parser** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports/exports for a case file.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## How it works (the real format, briefly)

Chrome/Chromium's Simple Cache backend stores each cached HTTP resource as one or more files on disk, named as a **16-hex-character lowercase hash of the cache key** (the cached URL), typically with a `_0`/`_1`/`_2`/`_3` stream-index suffix (e.g. `3a1f9c02de44b8a1_0`).

Each entry file has a fixed binary layout that this tool parses with Python's `struct` module:

**`SimpleFileHeader`** (at byte offset 0, little-endian):

| Field | Type | Notes |
|---|---|---|
| `initial_magic_number` | `uint64` | Must equal `0xfcfb6d1ba7725c30` |
| `version` | `uint32` | Format version |
| `key_length` | `uint32` | Length in bytes of the key string that follows |
| `key_hash` | `uint32` | Hash of the key |
| `key` | `key_length` bytes | The real cached URL (sometimes prefixed `_dk_<origin> ` for double-keyed/partitioned entries) |

**`SimpleFileEOF`** (fixed-size trailer at the **end** of the file, little-endian):

| Field | Type | Notes |
|---|---|---|
| `final_magic_number` | `uint32` | Must equal `0xFFFFFFFF` |
| `flags` | `uint32` | Bit 0 = a CRC32 was computed and stored |
| `data_crc32` | `uint32` | Stored CRC32 of the stream |
| `stream_size` | `uint32` | Size of the stream |

The region between the end of the header and the start of the EOF trailer holds the cached HTTP response stream. This tool real-computes `zlib.crc32` over that exact region and compares it to the stored value (see BCF-004), and does a best-effort regex scan of the same bytes for embedded HTTP header-line substrings (see the disclaimer above).

---

## Architecture

```
browser-cache-forensics-tool/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real Simple Cache binary parser (struct + zlib.crc32)
│   ├── detection_rules/      # 6 documented forensic detection rules (BCF-001..BCF-006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real constructed Simple Cache files + real host checks
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| BCF-001 | Insecure Cookie Transmission | Medium | Cache key is `http://` (not https) **and** the extracted response stream contains a `Set-Cookie:` header — evidence a cookie was sent/cached in cleartext |
| BCF-002 | Credentials Exposed in Cached URL | Medium | Cache key (URL) contains a credential/token-shaped query parameter (`password=`, `token=`, `api_key=`, `session=`, `auth=`) |
| BCF-003 | Cached Executable Download | Low | Extracted headers show an executable/binary `Content-Type` (`application/x-msdownload`, `application/octet-stream`) combined with a `.exe`/`.scr`/`.ps1` extension in the cached URL |
| BCF-004 | CRC32 Integrity Mismatch | Low | EOF trailer's CRC32-present flag is set, but the real computed `zlib.crc32` of the extracted stream bytes does **not** match the stored value |
| BCF-005 | Double-Keyed (Partitioned) Cache Entry | Low | Cache key contains Chromium's `_dk_` double-keying prefix (informational — cache partitioning note) |
| BCF-006 | Unrecognized Cache Entry Format | Low | Filename matched the Simple Cache naming convention but the leading 8 bytes did not match the Simple Cache magic number (corrupt, truncated, or a different cache backend) |

---

## Setup & Run

### Requirements
- Python 3.9+
- Any OS Python runs on (pure binary/byte parsing — no OS-specific APIs required to parse cache files)

### Install

```bash
git clone <this-repository-url>
cd browser-cache-forensics-tool
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
BCF_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/bcf.db`.

To point it at a real browser cache, find the `Cache_Data` directory for your browser/profile, for example:

- Chrome (Linux): `~/.config/google-chrome/Default/Cache/Cache_Data`
- Chromium (Linux): `~/.config/chromium/Default/Cache/Cache_Data`
- Edge (Linux): `~/.config/microsoft-edge/Default/Cache/Cache_Data`
- Chrome (Windows): `%LocalAppData%\Google\Chrome\User Data\Default\Cache\Cache_Data`
- Chrome (macOS): `~/Library/Caches/Google/Chrome/Default/Cache_Data`

### Run the CLI

```bash
python3 cli/main.py scan ~/.config/google-chrome/Default/Cache/Cache_Data --depth 4
python3 cli/main.py scan ~/.config/chromium/Default/Cache/Cache_Data --json
python3 cli/main.py scan /path/to/single/cache/entry_file --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI/triage gate) and `0` if the target is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

The test suite includes rule-level unit tests against synthetic context dicts, plus engine-level tests that build real, spec-conformant Simple Cache entry files byte-for-byte with `struct.pack` (real magic numbers, a real key string, real embedded `Set-Cookie:`/`Content-Type:` header substrings, and a real correctly-computed `zlib.crc32` for one entry vs. a deliberately wrong one for another) — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Browser Cache Forensics Tool check?**
It real-parses Chrome/Chromium Simple Cache entry files (`SimpleFileHeader` + `SimpleFileEOF` trailer) and flags cleartext cookie transmission, credentials embedded in cached URLs, cached executable downloads, CRC32 integrity mismatches, double-keyed/partitioned cache entries, and unrecognized/corrupt entries — using live struct-level byte parsing, never sample data.

**Who should use it?**
Digital forensics investigators, incident responders, DFIR students, and security engineers examining browser caches they own or are authorized to examine.

**Is it a replacement for a professional forensic tool or examiner?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does it fully deserialize the cached HTTP headers?**
No. Chromium's internal "Pickle" format for the cached response stream is largely undocumented outside the Chromium source. This tool does a documented, best-effort substring scan for header-line patterns rather than a full deserializer — see the Disclaimer.

**Does it work on the older `blockfile` cache backend?**
No, only the modern Simple Cache backend. `blockfile`-format caches (`data_0`..`data_3`, `index`) are out of scope.

**Does it modify my files?**
No. It only opens cache entry files for reading. It never writes to, deletes, or modifies any file it parses.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
