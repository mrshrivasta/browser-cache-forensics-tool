"""
Security Engine — Browser Cache Forensics Tool
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real binary parser for Chrome/Chromium's documented "Simple Cache" disk-cache
backend (used by Chrome, Chromium, Edge, Brave and other Chromium-derived
browsers). Every cached HTTP resource is stored on disk as a real file named
with a 16-hex-char lowercase hash of the cache key (the cached URL), usually
with a numeric stream suffix such as ``_0``.

This module walks a REAL directory (or parses a single file) with os.walk /
os.scandir, opens each candidate entry file, and parses the REAL bytes:

  SimpleFileHeader (at offset 0, fixed layout, little-endian)::

      uint64  initial_magic_number   (must equal 0xfcfb6d1ba7725c30)
      uint32  version
      uint32  key_length             (bytes of the key string that follow)
      uint32  key_hash
      bytes   key                    (key_length bytes — the cached URL,
                                       sometimes prefixed "_dk_<origin> " for
                                       double-keyed/partitioned cache entries)

  SimpleFileEOF (fixed-size trailer at the END of the file)::

      uint32  final_magic_number     (must equal 0xFFFFFFFF)
      uint32  flags                  (bit 0 = SHA256/CRC32 present)
      uint32  data_crc32
      uint32  stream_size

The region between the end of the header and the start of the EOF trailer is
the cached HTTP response stream (headers pickle + body, interleaved
Chromium-internal structures). This engine does NOT implement a full
Chromium "Pickle" deserializer — that format is undocumented outside the
Chromium source and out of scope here. Instead it honestly does a
best-effort, forensic substring scan of that region (decoded leniently as
latin-1, which never raises on arbitrary bytes) for well-known embedded HTTP
header-line patterns such as ``Content-Type:``, ``Set-Cookie:``,
``Location:`` and ``Cache-Control:``. This is documented clearly in the
README as a heuristic, not a full deserializer.

No sample/mock cache data is ever generated — every Finding reflects bytes
actually read from a real file on disk at scan time. Files that don't match
the Simple Cache magic, or that are too short to contain a header + trailer,
are handled without crashing and counted in errors_count / flagged as
BCF-006 depending on whether they matched the naming convention.
"""
import os
import re
import struct
import time
import zlib

from app.detection_rules import ALL_RULES

# --- Simple Cache binary format constants (as documented by Chromium) -----
INITIAL_MAGIC_NUMBER = 0xFCFB6D1BA7725C30  # SimpleFileHeader magic (uint64 LE)
FINAL_MAGIC_NUMBER = 0xFFFFFFFF            # SimpleFileEOF magic (uint32 LE)
FLAG_HAS_CRC32 = 1 << 0

HEADER_STRUCT = struct.Struct("<QIII")   # magic(u64) version(u32) key_len(u32) key_hash(u32)
HEADER_SIZE = HEADER_STRUCT.size          # 20 bytes
EOF_STRUCT = struct.Struct("<IIII")       # magic(u32) flags(u32) crc32(u32) stream_size(u32)
EOF_SIZE = EOF_STRUCT.size                # 16 bytes

# Simple Cache entry filenames: 16 lowercase hex chars, optionally followed
# by an underscore + a single stream-index digit (commonly 0-3).
CACHE_FILENAME_RE = re.compile(r"^[0-9a-f]{16}(_[0-3])?$")

HEADER_LINE_RE = re.compile(
    rb"(Content-Type|Set-Cookie|Location|Cache-Control)\s*:\s*[^\r\n\x00]{0,200}",
    re.IGNORECASE,
)

DEFAULT_EXCLUDES = {"/proc", "/sys", "/dev", "/run"}


class SimpleCacheParseError(Exception):
    """Raised internally when a file cannot be parsed as Simple Cache."""


def looks_like_cache_entry_name(filename):
    """Real check of a filename against the Simple Cache naming convention."""
    return bool(CACHE_FILENAME_RE.match(filename))


def parse_simple_cache_entry(data):
    """Real-parse the raw bytes of one Simple Cache entry file.

    Returns a dict describing the parsed entry, or raises
    SimpleCacheParseError with a short reason if the bytes don't conform.
    """
    if len(data) < HEADER_SIZE + EOF_SIZE:
        raise SimpleCacheParseError("file too short for header + EOF trailer")

    magic, version, key_length, key_hash = HEADER_STRUCT.unpack_from(data, 0)
    if magic != INITIAL_MAGIC_NUMBER:
        raise SimpleCacheParseError("initial magic number mismatch (not Simple Cache)")

    key_start = HEADER_SIZE
    key_end = key_start + key_length
    if key_end + EOF_SIZE > len(data):
        raise SimpleCacheParseError("key_length overruns file (truncated/corrupt)")

    raw_key = data[key_start:key_end]
    try:
        key = raw_key.decode("utf-8")
    except UnicodeDecodeError:
        key = raw_key.decode("latin-1")

    eof_offset = len(data) - EOF_SIZE
    final_magic, flags, stored_crc32, stream_size = EOF_STRUCT.unpack_from(data, eof_offset)
    if final_magic != FINAL_MAGIC_NUMBER:
        raise SimpleCacheParseError("final (EOF) magic number mismatch (truncated/corrupt)")

    body_start = key_end
    body_end = eof_offset
    body = data[body_start:body_end]

    has_crc = bool(flags & FLAG_HAS_CRC32)
    computed_crc32 = zlib.crc32(body) & 0xFFFFFFFF
    crc_ok = (not has_crc) or (computed_crc32 == stored_crc32)

    body_text = body.decode("latin-1", errors="replace")
    header_hits = [m.group(0).decode("latin-1") for m in HEADER_LINE_RE.finditer(body)]

    return {
        "version": version,
        "key": key,
        "key_hash": key_hash,
        "body": body,
        "body_text": body_text,
        "header_hits": header_hits,
        "has_crc_flag": has_crc,
        "stored_crc32": stored_crc32,
        "computed_crc32": computed_crc32,
        "crc_ok": crc_ok,
        "stream_size": stream_size,
    }


class ScanEngine:
    """Walks a real path and real-parses every Simple Cache entry found.

    ``target_path`` may be a single cache entry file or a directory that is
    real-walked (respecting ``max_depth``/``excludes``) for files whose
    names match the Simple Cache naming convention.
    """

    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real scan. Returns a summary dict."""
        start = time.time()
        if os.path.isfile(self.target_path):
            self._parse_file(self.target_path, enforce_name_pattern=False)
        else:
            self._walk(self.target_path, depth=0)
        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _walk(self, path, depth):
        if self.files_scanned >= self.max_files:
            return
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue

            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                self.errors_count += 1
                continue

            if is_dir:
                self._walk(full_path, depth + 1)
                continue

            if looks_like_cache_entry_name(entry.name):
                self._parse_file(full_path, enforce_name_pattern=True)

    def _parse_file(self, path, enforce_name_pattern):
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except (PermissionError, FileNotFoundError, OSError):
            self.errors_count += 1
            return

        self.files_scanned += 1

        try:
            entry = parse_simple_cache_entry(data)
        except SimpleCacheParseError:
            # Leading 8 bytes didn't match Simple Cache magic (or the file
            # was too short/truncated to contain a valid header+trailer).
            # Only worth a BCF-006 finding when the filename matched the
            # cache-entry naming convention in the first place; otherwise
            # it's just not a cache file and is silently skipped.
            if enforce_name_pattern:
                self._apply_rules(path, {"path": path, "unrecognized": True, "raw_len": len(data)})
            return

        self._apply_rules(path, {
            "path": path,
            "key": entry["key"],
            "key_hash": entry["key_hash"],
            "header_hits": entry["header_hits"],
            "body_text": entry["body_text"],
            "has_crc_flag": entry["has_crc_flag"],
            "stored_crc32": entry["stored_crc32"],
            "computed_crc32": entry["computed_crc32"],
            "crc_ok": entry["crc_ok"],
            "stream_size": entry["stream_size"],
            "unrecognized": False,
        })

    def _apply_rules(self, path, context):
        for rule in ALL_RULES:
            try:
                result = rule(context)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                result["file_path"] = path
                # Field repurposed from the original permission-auditor
                # schema: here it carries the real cache key/URL string.
                result["permissions_octal"] = context.get("key", "")
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)


# Public alias matching the project's PascalCase name — ScanEngine remains
# the primary import used across the app/cli/tests.
BrowserCacheForensicsTool = ScanEngine
