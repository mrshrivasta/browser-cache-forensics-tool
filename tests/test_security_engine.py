"""Tests for the Security Engine and Detection Rules.

Two layers of REAL testing, no mocking of parsing logic:

1. Rule-level unit tests that call each detection rule directly with a
   synthetic context dict (fast, isolates rule logic).
2. Engine-level tests that BUILD real, spec-conformant Simple Cache entry
   files byte-for-byte with struct.pack (real 8-byte magic, real header
   fields, a real UTF-8 key string, real body bytes containing real
   'Set-Cookie:'/'Content-Type:' substrings, and a real EOF trailer with a
   correctly-computed zlib.crc32 for one entry and a deliberately wrong CRC
   for another), write them to real temp files, and run the actual
   ScanEngine against them on disk.
"""
import os
import struct
import tempfile
import shutil
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import (
    ScanEngine,
    parse_simple_cache_entry,
    INITIAL_MAGIC_NUMBER,
    FINAL_MAGIC_NUMBER,
    FLAG_HAS_CRC32,
    HEADER_STRUCT,
    EOF_STRUCT,
)
from app.detection_rules import (
    rule_insecure_cookie_transmission,
    rule_credentials_in_cached_url,
    rule_cached_executable_download,
    rule_crc_integrity_mismatch,
    rule_double_keyed_cache_entry,
    rule_unrecognized_cache_format,
    ALL_RULES,
)


# ---------------------------------------------------------------------------
# Helper: build real, spec-conformant Simple Cache entry bytes
# ---------------------------------------------------------------------------

def build_simple_cache_entry(key: str, body: bytes, version=1, key_hash=0,
                              wrong_crc=False, set_crc_flag=True):
    """Real-construct the exact byte layout of a Simple Cache entry file:
    SimpleFileHeader + body stream + SimpleFileEOF trailer."""
    key_bytes = key.encode("utf-8")
    header = HEADER_STRUCT.pack(INITIAL_MAGIC_NUMBER, version, len(key_bytes), key_hash)

    real_crc = zlib.crc32(body) & 0xFFFFFFFF
    stored_crc = (real_crc ^ 0xDEADBEEF) & 0xFFFFFFFF if wrong_crc else real_crc
    flags = FLAG_HAS_CRC32 if set_crc_flag else 0

    eof = EOF_STRUCT.pack(FINAL_MAGIC_NUMBER, flags, stored_crc, len(body))
    return header + key_bytes + body + eof


def write_entry(dirpath, filename, entry_bytes):
    path = os.path.join(dirpath, filename)
    with open(path, "wb") as fh:
        fh.write(entry_bytes)
    return path


# ---------------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts)
# ---------------------------------------------------------------------------

def test_rule_insecure_cookie_transmission_fires_on_http_with_set_cookie():
    ctx = {
        "key": "http://example.com/login",
        "header_hits": ["Set-Cookie: session=abc123; Path=/"],
    }
    result = rule_insecure_cookie_transmission(ctx)
    assert result is not None
    assert result["rule_id"] == "BCF-001"


def test_rule_insecure_cookie_transmission_silent_on_https():
    ctx = {
        "key": "https://example.com/login",
        "header_hits": ["Set-Cookie: session=abc123; Path=/"],
    }
    assert rule_insecure_cookie_transmission(ctx) is None


def test_rule_insecure_cookie_transmission_silent_without_cookie():
    ctx = {"key": "http://example.com/", "header_hits": ["Content-Type: text/html"]}
    assert rule_insecure_cookie_transmission(ctx) is None


def test_rule_credentials_in_cached_url_detects_password_param():
    ctx = {"key": "http://example.com/login?password=hunter2"}
    result = rule_credentials_in_cached_url(ctx)
    assert result is not None
    assert result["rule_id"] == "BCF-002"


def test_rule_credentials_in_cached_url_detects_token_param():
    ctx = {"key": "https://api.example.com/data?token=eyJabc.def"}
    result = rule_credentials_in_cached_url(ctx)
    assert result["rule_id"] == "BCF-002"


def test_rule_credentials_in_cached_url_silent_on_clean_url():
    ctx = {"key": "https://example.com/index.html?page=2"}
    assert rule_credentials_in_cached_url(ctx) is None


def test_rule_cached_executable_download_fires_on_exe_with_octet_stream():
    ctx = {
        "key": "http://downloads.example.com/setup.exe",
        "header_hits": ["Content-Type: application/octet-stream"],
    }
    result = rule_cached_executable_download(ctx)
    assert result is not None
    assert result["rule_id"] == "BCF-003"


def test_rule_cached_executable_download_silent_without_matching_extension():
    ctx = {
        "key": "http://downloads.example.com/readme.txt",
        "header_hits": ["Content-Type: application/octet-stream"],
    }
    assert rule_cached_executable_download(ctx) is None


def test_rule_crc_integrity_mismatch_fires_when_crc_wrong():
    ctx = {
        "key": "http://example.com/asset.js",
        "has_crc_flag": True,
        "crc_ok": False,
        "stored_crc32": 0x11111111,
        "computed_crc32": 0x22222222,
    }
    result = rule_crc_integrity_mismatch(ctx)
    assert result is not None
    assert result["rule_id"] == "BCF-004"


def test_rule_crc_integrity_mismatch_silent_when_crc_ok():
    ctx = {"key": "http://example.com/asset.js", "has_crc_flag": True, "crc_ok": True}
    assert rule_crc_integrity_mismatch(ctx) is None


def test_rule_double_keyed_cache_entry_detects_dk_prefix():
    ctx = {"key": "_dk_https://top.example.com http://sub.example.com/img.png"}
    result = rule_double_keyed_cache_entry(ctx)
    assert result is not None
    assert result["rule_id"] == "BCF-005"


def test_rule_unrecognized_cache_format_fires_on_unrecognized_flag():
    ctx = {"unrecognized": True, "path": "/tmp/x/abcdef0123456789_0", "raw_len": 4}
    result = rule_unrecognized_cache_format(ctx)
    assert result is not None
    assert result["rule_id"] == "BCF-006"


def test_all_rules_are_pure_functions_returning_none_or_dict():
    ctx = {"key": "https://example.com/", "header_hits": [], "unrecognized": False,
           "has_crc_flag": False, "crc_ok": True}
    for rule in ALL_RULES:
        result = rule(ctx)
        assert result is None or isinstance(result, dict)


# ---------------------------------------------------------------------------
# Engine-level tests against REAL constructed Simple Cache entry files
# ---------------------------------------------------------------------------

def test_parse_simple_cache_entry_round_trip():
    body = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
    entry_bytes = build_simple_cache_entry("https://example.com/", body)
    parsed = parse_simple_cache_entry(entry_bytes)
    assert parsed["key"] == "https://example.com/"
    assert parsed["crc_ok"] is True
    assert "Content-Type: text/html" in parsed["header_hits"][0]


def test_engine_detects_insecure_cookie_and_credentials_in_real_files():
    tmpdir = tempfile.mkdtemp()
    try:
        cookie_body = (
            b"HTTP/1.1 200 OK\r\nSet-Cookie: sessionid=deadbeef; HttpOnly\r\n"
            b"Content-Type: text/html\r\n\r\n<html>login</html>"
        )
        entry1 = build_simple_cache_entry(
            "http://example.com/login?password=hunter2", cookie_body
        )
        write_entry(tmpdir, "0123456789abcdef_0", entry1)

        engine = ScanEngine(tmpdir, max_depth=2)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BCF-001" in rule_ids
        assert "BCF-002" in rule_ids
        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0

        cookie_finding = next(f for f in result["findings"] if f["rule_id"] == "BCF-001")
        assert cookie_finding["permissions_octal"] == "http://example.com/login?password=hunter2"
        assert cookie_finding["owner_uid"] is None
        assert cookie_finding["owner_gid"] is None
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_cached_executable_download():
    tmpdir = tempfile.mkdtemp()
    try:
        body = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-msdownload\r\n\r\nMZ\x90\x00"
        entry = build_simple_cache_entry("http://files.example.com/tool.exe", body)
        write_entry(tmpdir, "abcdef0123456789_0", entry)

        engine = ScanEngine(tmpdir, max_depth=2)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BCF-003" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_double_keyed_entry():
    tmpdir = tempfile.mkdtemp()
    try:
        body = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG"
        entry = build_simple_cache_entry(
            "_dk_https://top.example.com https://cdn.example.com/pixel.png", body
        )
        write_entry(tmpdir, "1111222233334444_1", entry)

        engine = ScanEngine(tmpdir, max_depth=2)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BCF-005" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_computes_real_crc32_and_flags_mismatch():
    """BCF-004: build one entry with a correct real zlib.crc32 (no finding)
    and one with a deliberately wrong stored CRC (finding fires) — the
    engine must actually compute zlib.crc32 over the real extracted body
    bytes and compare it, not just trust a flag."""
    tmpdir = tempfile.mkdtemp()
    try:
        body = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello world"

        good_entry = build_simple_cache_entry(
            "https://example.com/good.txt", body, wrong_crc=False
        )
        bad_entry = build_simple_cache_entry(
            "https://example.com/bad.txt", body, wrong_crc=True
        )
        write_entry(tmpdir, "aaaaaaaaaaaaaaaa_0", good_entry)
        write_entry(tmpdir, "bbbbbbbbbbbbbbbb_0", bad_entry)

        engine = ScanEngine(tmpdir, max_depth=2)
        result = engine.run()

        assert result["files_scanned"] == 2
        crc_findings = [f for f in result["findings"] if f["rule_id"] == "BCF-004"]
        assert len(crc_findings) == 1
        assert "bad.txt" in crc_findings[0]["permissions_octal"]
    finally:
        shutil.rmtree(tmpdir)


def test_engine_flags_unrecognized_format_for_matching_filename():
    tmpdir = tempfile.mkdtemp()
    try:
        # Filename matches the naming convention but content is garbage —
        # no valid Simple Cache magic at all.
        path = os.path.join(tmpdir, "0000111122223333_0")
        with open(path, "wb") as fh:
            fh.write(b"not a real cache entry, way too short and wrong magic")

        engine = ScanEngine(tmpdir, max_depth=2)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BCF-006" in rule_ids
        assert result["files_scanned"] == 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_ignores_files_not_matching_naming_convention():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "index.html"), "w") as fh:
            fh.write("not a cache entry file")
        with open(os.path.join(tmpdir, "README.txt"), "w") as fh:
            fh.write("also not a cache entry file")

        engine = ScanEngine(tmpdir, max_depth=2)
        result = engine.run()
        assert result["files_scanned"] == 0
        assert result["findings"] == []
    finally:
        shutil.rmtree(tmpdir)


def test_engine_parses_single_file_target_directly():
    tmpdir = tempfile.mkdtemp()
    try:
        body = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
        entry = build_simple_cache_entry("https://example.com/solo", body)
        # Non-conforming filename — but a direct file target is still parsed.
        path = write_entry(tmpdir, "solo_cache_file.bin", entry)

        engine = ScanEngine(path)
        result = engine.run()
        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_engine_handles_unreadable_directory_without_crashing():
    engine = ScanEngine("/this/path/does/not/exist", max_depth=2)
    result = engine.run()
    assert result["files_scanned"] == 0
    assert result["errors_count"] >= 1
    assert result["findings"] == []
