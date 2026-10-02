from secret_sentry.scanner import scan_path, scan_text


def test_detects_and_redacts_credential_assignment():
    results = scan_text('api_key = "not-a-real-but-long-secret"')
    assert results[0].rule == "credential-assignment"
    assert results[0].redacted == "[redacted]"


def test_inline_ignore_and_binary_skip(tmp_path):
    (tmp_path / "example.py").write_text('token = "placeholder-secret-value" # secret-scan: ignore\n', encoding="utf-8")
    (tmp_path / "image.bin").write_bytes(b"\x00private")
    findings, checked, skipped = scan_path(tmp_path)
    assert findings == []
    assert checked == 1
    assert skipped == 1
