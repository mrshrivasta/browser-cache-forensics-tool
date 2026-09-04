"""
Detection Rules — Browser Cache Forensics Tool
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL context dict produced by parsing one Simple Cache
entry file's actual bytes (see app.security_engine.parse_simple_cache_entry)
and returns a Finding dict if the condition is met. Rules operate purely on
the passed-in dict so they can be unit tested with synthetic contexts, and
are documented so results can be independently verified by inspecting the
same cache file with any hex editor.

Context dict shape (see ScanEngine._apply_rules)::

    {
        "path": str,                 # real file path on disk
        "key": str,                  # real cache key / cached URL
        "key_hash": int,
        "header_hits": [str, ...],   # real substrings matched from the body
        "body_text": str,            # real body bytes decoded latin-1
        "has_crc_flag": bool,
        "stored_crc32": int,
        "computed_crc32": int,
        "crc_ok": bool,
        "stream_size": int,
        "unrecognized": bool,        # True if magic didn't match at all
    }
"""

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

CREDENTIAL_PARAM_MARKERS = ("password=", "token=", "api_key=", "session=", "auth=")
EXECUTABLE_CONTENT_TYPES = ("application/x-msdownload", "application/octet-stream")
EXECUTABLE_URL_EXTENSIONS = (".exe", ".scr", ".ps1")


def _headers_blob(context):
    return " ".join(context.get("header_hits") or [])


def rule_insecure_cookie_transmission(context):
    """BCF-001: The cache key shows the resource was fetched over plaintext
    http:// AND the cached response stream contains a Set-Cookie: header —
    forensic evidence that a session/tracking cookie was transmitted (and
    cached) in cleartext, exposed to network interception."""
    if context.get("unrecognized"):
        return None
    key = context.get("key", "")
    headers = _headers_blob(context)
    if key.lower().startswith("http://") and "set-cookie:" in headers.lower():
        return {
            "rule_id": "BCF-001",
            "rule_name": "Insecure Cookie Transmission",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Cached entry for {key} was fetched over plaintext HTTP and its "
                f"cached response includes a Set-Cookie header — evidence a "
                f"cookie was transmitted (and is now recoverable from disk cache) "
                f"in cleartext."
            ),
        }
    return None


def rule_credentials_in_cached_url(context):
    """BCF-002: The cache key (cached URL) itself contains a credential- or
    token-shaped query parameter (password=, token=, api_key=, session=,
    auth=). URLs are logged/cached widely (browser history, proxies, cache),
    so secrets embedded in a URL are forensically significant exposure."""
    if context.get("unrecognized"):
        return None
    key = context.get("key", "")
    lowered = key.lower()
    hit = next((m for m in CREDENTIAL_PARAM_MARKERS if m in lowered), None)
    if hit:
        return {
            "rule_id": "BCF-002",
            "rule_name": "Credentials Exposed in Cached URL",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Cached entry key contains a credential-shaped query parameter "
                f"('{hit.rstrip('=')}') in {key} — secrets embedded in URLs persist "
                f"in browser cache/history long after use."
            ),
        }
    return None


def rule_cached_executable_download(context):
    """BCF-003: The cached response stream shows an executable/script
    Content-Type combined with an executable file extension visible in the
    cached URL — evidence a potentially malicious or unwanted binary was
    downloaded and its response is still recoverable from cache."""
    if context.get("unrecognized"):
        return None
    key = context.get("key", "")
    headers = _headers_blob(context).lower()
    lowered_key = key.lower()
    has_exec_content_type = any(ct in headers for ct in EXECUTABLE_CONTENT_TYPES)
    has_exec_extension = any(lowered_key.split("?")[0].endswith(ext) for ext in EXECUTABLE_URL_EXTENSIONS)
    if has_exec_content_type and has_exec_extension:
        return {
            "rule_id": "BCF-003",
            "rule_name": "Cached Executable Download",
            "severity": SEVERITY_LOW,
            "description": (
                f"Cached entry for {key} has an executable/binary Content-Type "
                f"and an executable file extension — evidence of a downloaded "
                f"executable/script whose response body may still be recoverable "
                f"from disk cache."
            ),
        }
    return None


def rule_crc_integrity_mismatch(context):
    """BCF-004: The SimpleFileEOF trailer's flags indicate a CRC32 was
    stored for this stream, but the real zlib.crc32 computed over the actual
    extracted body bytes does not match the stored value — an integrity
    anomaly (bit rot, manual tampering, or a parsing offset error) worth
    flagging for further review."""
    if context.get("unrecognized"):
        return None
    if context.get("has_crc_flag") and not context.get("crc_ok", True):
        key = context.get("key", "")
        return {
            "rule_id": "BCF-004",
            "rule_name": "CRC32 Integrity Mismatch",
            "severity": SEVERITY_LOW,
            "description": (
                f"Cached entry for {key} declares a stored CRC32 "
                f"(0x{context.get('stored_crc32', 0):08x}) that does not match the "
                f"computed CRC32 (0x{context.get('computed_crc32', 0):08x}) of its "
                f"extracted stream bytes — possible corruption or tampering."
            ),
        }
    return None


def rule_double_keyed_cache_entry(context):
    """BCF-005: The cache key carries Chromium's '_dk_' double-key prefix,
    meaning this entry is partitioned by top-level site (network state
    partitioning / storage partitioning). Informational: useful for an
    investigator to know which top-level context loaded this resource."""
    if context.get("unrecognized"):
        return None
    key = context.get("key", "")
    if "_dk_" in key:
        return {
            "rule_id": "BCF-005",
            "rule_name": "Double-Keyed (Partitioned) Cache Entry",
            "severity": SEVERITY_LOW,
            "description": (
                f"Cache key {key} uses the '_dk_' double-keying prefix, indicating "
                f"this entry is partitioned by top-level site. The prefix encodes "
                f"the top-level origin the resource was loaded under."
            ),
        }
    return None


def rule_unrecognized_cache_format(context):
    """BCF-006: A file whose name matched the Simple Cache naming
    convention (16 hex chars, optional _N suffix) but whose leading 8 bytes
    did not match the documented Simple Cache initial magic number — an
    unrecognized/corrupt entry, or a file from a different cache backend
    (e.g. the older 'blockfile' format), flagged as a parse note rather than
    silently skipped."""
    if context.get("unrecognized"):
        return {
            "rule_id": "BCF-006",
            "rule_name": "Unrecognized Cache Entry Format",
            "severity": SEVERITY_LOW,
            "description": (
                f"{context.get('path')} matches the Simple Cache filename "
                f"convention but its header did not match the documented Simple "
                f"Cache magic number ({context.get('raw_len', 0)} bytes read) — "
                f"unrecognized, truncated, or corrupt entry."
            ),
        }
    return None


ALL_RULES = [
    rule_insecure_cookie_transmission,
    rule_credentials_in_cached_url,
    rule_cached_executable_download,
    rule_crc_integrity_mismatch,
    rule_double_keyed_cache_entry,
    rule_unrecognized_cache_format,
]
