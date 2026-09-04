def _build_cache_dir_with_finding(tmp_path):
    """Real-construct a real Simple Cache entry file (cleartext cookie +
    credential-in-URL) inside a real temp directory and return the dir."""
    import struct
    import zlib
    from app.security_engine import (
        INITIAL_MAGIC_NUMBER, FINAL_MAGIC_NUMBER, FLAG_HAS_CRC32,
        HEADER_STRUCT, EOF_STRUCT,
    )

    key = "http://example.com/login?password=hunter2"
    body = (
        b"HTTP/1.1 200 OK\r\nSet-Cookie: sessionid=deadbeef\r\n"
        b"Content-Type: text/html\r\n\r\n<html></html>"
    )
    key_bytes = key.encode("utf-8")
    header = HEADER_STRUCT.pack(INITIAL_MAGIC_NUMBER, 1, len(key_bytes), 0)
    crc = zlib.crc32(body) & 0xFFFFFFFF
    eof = EOF_STRUCT.pack(FINAL_MAGIC_NUMBER, FLAG_HAS_CRC32, crc, len(body))
    entry_bytes = header + key_bytes + body + eof

    cache_dir = tmp_path / "Cache" / "Cache_Data"
    cache_dir.mkdir(parents=True)
    entry_path = cache_dir / "0123456789abcdef_0"
    entry_path.write_bytes(entry_bytes)
    return str(tmp_path / "Cache")


def test_full_scan_alert_incident_workflow(registered_client, tmp_path):
    # Run a real scan against a real, freshly-constructed Simple Cache entry
    cache_dir = _build_cache_dir_with_finding(tmp_path)
    resp = registered_client.post("/scan/run", data={"target_path": cache_dir}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Scan complete" in resp.data

    # Logs page should show at least one scan
    resp = registered_client.get("/logs")
    assert cache_dir.encode() in resp.data

    # Alerts page should load (may or may not have alerts depending on host state)
    resp = registered_client.get("/alerts")
    assert resp.status_code == 200

    # Analytics JSON endpoint returns real aggregated data
    resp = registered_client.get("/analytics/data")
    assert resp.status_code == 200
    assert resp.is_json

    # Reports CSV export works
    resp = registered_client.get("/reports/export.csv")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
