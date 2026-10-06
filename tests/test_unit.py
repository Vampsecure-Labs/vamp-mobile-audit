# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests unitarios para vamp-mobile-audit."""
import io
import plistlib
import zipfile
from typing import List

from vamp_mobile_audit import (
    Finding,
    analyze_apk,
    analyze_ipa,
    build_report,
    check_ats_arbitrary_loads,
    check_ats_domain_exceptions,
    check_backup,
    check_cleartext,
    check_dangerous_permissions,
    check_debuggable,
    check_exported_components,
    check_file_sharing,
    check_http_urls,
    check_no_network_security_config,
    check_privacy_descriptions,
    check_secrets_in_plist,
    check_secrets_in_strings,
    check_url_schemes,
    check_weak_crypto,
    extract_dex_strings,
    main,
    render_html,
)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def make_ipa(plist_dict: dict) -> bytes:
    """Crea un IPA sintético (ZIP) con un Info.plist dado."""
    buf = io.BytesIO()
    plist_data = plistlib.dumps(plist_dict, fmt=plistlib.FMT_XML)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/TestApp.app/Info.plist", plist_data)
    return buf.getvalue()


def make_apk(manifest_xml: str, extra_strings: List[str] = None, extra_names: List[str] = None) -> bytes:
    """Crea un APK sintético con AndroidManifest.xml en texto plano (fallback path)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        if extra_names:
            for name in extra_names:
                zf.writestr(name, b"")
    return buf.getvalue()


_MANIFEST_BASE = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app">
  {body}
</manifest>"""


# ─── APK check: debuggable ───────────────────────────────────────────────────

def test_debuggable_true():
    elems = [("application", {"debuggable": "true"})]
    f = check_debuggable(elems)
    assert f is not None
    assert f.check_id == "MOBILE-001"
    assert f.severity == "critical"


def test_debuggable_false():
    elems = [("application", {"debuggable": "false"})]
    assert check_debuggable(elems) is None


def test_debuggable_absent():
    elems = [("application", {})]
    assert check_debuggable(elems) is None


# ─── APK check: backup ───────────────────────────────────────────────────────

def test_backup_allowed_by_default():
    elems = [("application", {})]
    f = check_backup(elems)
    assert f is not None
    assert f.check_id == "MOBILE-002"
    assert f.severity == "high"


def test_backup_explicitly_disabled():
    elems = [("application", {"allowBackup": "false"})]
    assert check_backup(elems) is None


def test_backup_explicitly_true():
    elems = [("application", {"allowBackup": "true"})]
    f = check_backup(elems)
    assert f is not None
    assert "true" in f.evidence[0]


# ─── APK check: cleartext ────────────────────────────────────────────────────

def test_cleartext_explicit():
    elems = [("application", {"usesCleartextTraffic": "true"})]
    f = check_cleartext(elems, [])
    assert f is not None
    assert f.check_id == "MOBILE-003"


def test_cleartext_disabled():
    elems = [("application", {"usesCleartextTraffic": "false"})]
    assert check_cleartext(elems, []) is None


# ─── APK check: exported components ─────────────────────────────────────────

def test_exported_without_permission():
    elems = [
        ("application", {}),
        ("activity", {"name": "com.test.MainActivity", "exported": "true"}),
    ]
    f = check_exported_components(elems)
    assert f is not None
    assert f.check_id == "MOBILE-004"
    assert "MainActivity" in f.evidence[0]


def test_exported_with_permission_ok():
    elems = [("activity", {"name": "com.test.A", "exported": "true", "permission": "com.test.PERM"})]
    assert check_exported_components(elems) is None


def test_not_exported():
    elems = [("activity", {"name": "com.test.A", "exported": "false"})]
    assert check_exported_components(elems) is None


# ─── APK check: secrets ──────────────────────────────────────────────────────

def test_secrets_google_api_key():
    strings = ["AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ12345678"]
    f = check_secrets_in_strings(strings)
    assert f is not None
    assert f.check_id == "MOBILE-005"
    assert f.severity == "critical"


def test_secrets_github_token():
    strings = ["ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"]  # 40-char suffix ≥36
    f = check_secrets_in_strings(strings)
    assert f is not None


def test_secrets_clean():
    strings = ["hello world", "com.example.app", "2026-10-06"]
    assert check_secrets_in_strings(strings) is None


# ─── APK check: dangerous permissions ───────────────────────────────────────

def test_dangerous_permission_camera():
    elems = [("uses-permission", {"name": "android.permission.CAMERA"})]
    f = check_dangerous_permissions(elems)
    assert f is not None
    assert f.check_id == "MOBILE-006"
    assert f.severity == "medium"


def test_safe_permission():
    elems = [("uses-permission", {"name": "android.permission.INTERNET"})]
    assert check_dangerous_permissions(elems) is None


# ─── APK check: weak crypto ──────────────────────────────────────────────────

def test_weak_crypto_des():
    strings = ["DES/ECB/PKCS5Padding", "some other string"]
    f = check_weak_crypto(strings)
    assert f is not None
    assert f.check_id == "MOBILE-007"


def test_weak_crypto_rc4():
    strings = ["RC4", "AES/CBC/PKCS5Padding"]
    f = check_weak_crypto(strings)
    assert f is not None


def test_strong_crypto_ok():
    strings = ["AES/CBC/PKCS5Padding", "AES/GCM/NoPadding"]
    assert check_weak_crypto(strings) is None


# ─── APK check: HTTP URLs ────────────────────────────────────────────────────

def test_http_url_detected():
    strings = ["http://api.example.com/endpoint", "https://secure.example.com"]
    f = check_http_urls(strings)
    assert f is not None
    assert f.check_id == "MOBILE-008"
    assert "http://api.example.com" in f.evidence[0]


def test_https_only_ok():
    strings = ["https://api.example.com/endpoint"]
    assert check_http_urls(strings) is None


def test_localhost_http_ignored():
    strings = ["http://localhost:8080/test", "http://127.0.0.1/debug"]
    assert check_http_urls(strings) is None


# ─── APK check: network_security_config ──────────────────────────────────────

def test_no_nsc():
    names = ["AndroidManifest.xml", "classes.dex"]
    f = check_no_network_security_config(names)
    assert f is not None
    assert f.check_id == "MOBILE-009"


def test_has_nsc():
    names = ["AndroidManifest.xml", "res/xml/network_security_config.xml"]
    assert check_no_network_security_config(names) is None


# ─── IPA checks ──────────────────────────────────────────────────────────────

def test_ats_arbitrary_loads_true():
    plist = {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
    f = check_ats_arbitrary_loads(plist)
    assert f is not None
    assert f.check_id == "MOBILE-010"
    assert f.severity == "critical"


def test_ats_arbitrary_loads_absent():
    assert check_ats_arbitrary_loads({}) is None


def test_file_sharing_enabled():
    plist = {"UIFileSharingEnabled": True}
    f = check_file_sharing(plist)
    assert f is not None
    assert f.check_id == "MOBILE-011"


def test_file_sharing_disabled():
    assert check_file_sharing({"UIFileSharingEnabled": False}) is None


def test_secrets_in_plist_api_key():
    plist = {"SomeAPIKey": "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ12345678"}
    f = check_secrets_in_plist(plist)
    assert f is not None
    assert f.check_id == "MOBILE-012"


def test_secrets_in_plist_clean():
    plist = {"CFBundleDisplayName": "TestApp", "CFBundleVersion": "1.0"}
    assert check_secrets_in_plist(plist) is None


def test_url_schemes_custom():
    plist = {"CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp", "testscheme"]}]}
    f = check_url_schemes(plist)
    assert f is not None
    assert f.check_id == "MOBILE-013"
    assert "myapp" in f.evidence[0]


def test_url_schemes_http_only():
    plist = {"CFBundleURLTypes": [{"CFBundleURLSchemes": ["https"]}]}
    assert check_url_schemes(plist) is None


def test_ats_domain_exceptions():
    plist = {
        "NSAppTransportSecurity": {
            "NSExceptionDomains": {
                "insecure.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True}
            }
        }
    }
    f = check_ats_domain_exceptions(plist)
    assert f is not None
    assert f.check_id == "MOBILE-014"
    assert "insecure.example.com" in f.evidence[0]


def test_ats_no_exceptions():
    plist = {"NSAppTransportSecurity": {"NSExceptionDomains": {}}}
    assert check_ats_domain_exceptions(plist) is None


def test_privacy_missing():
    plist = {"CFBundleDisplayName": "TestApp"}
    f = check_privacy_descriptions(plist)
    assert f is not None
    assert f.check_id == "MOBILE-015"
    assert len(f.evidence) >= 1


def test_privacy_all_present():
    from vamp_mobile_audit import PRIVACY_KEYS_REQUIRED
    plist = {k: f"Usamos {k}" for k in PRIVACY_KEYS_REQUIRED}
    assert check_privacy_descriptions(plist) is None


# ─── Report / output ─────────────────────────────────────────────────────────

def test_build_report_structure(tmp_path):
    dummy = tmp_path / "app.apk"
    dummy.write_bytes(b"PK\x03\x04")  # minimal ZIP magic
    findings = [
        Finding.from_check("MOBILE-001", "debuggable", ["evidence"])
    ]
    r = build_report(str(dummy), "android", findings, "CASE-001", "Tester")
    assert r["platform"] == "android"
    assert r["summary"]["critical"] == 1
    assert r["summary"]["total"] == 1
    assert r["case_id"] == "CASE-001"
    assert len(r["findings"]) == 1
    assert r["findings"][0]["check_id"] == "MOBILE-001"


def test_render_html_contains_finding():
    findings = [Finding.from_check("MOBILE-010", "ATS disabled", ["NSAllowsArbitraryLoads=true"])]
    report = {
        "target": "test.ipa", "platform": "ios", "sha256": "abc" * 10,
        "timestamp": "2026-10-06T00:00:00+00:00", "case_id": "", "analyst": "",
        "findings": [f.to_dict() for f in findings],
        "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1},
    }
    h = render_html(report)
    assert "MOBILE-010" in h
    assert "NSAllowsArbitraryLoads" in h
    assert "critical" in h.lower()


# ─── Integrate: analyze_ipa con fixture sintético ────────────────────────────

def test_analyze_ipa_insecure(tmp_path):
    plist = {
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        "UIFileSharingEnabled": True,
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp"]}],
    }
    ipa_path = tmp_path / "test.ipa"
    ipa_path.write_bytes(make_ipa(plist))
    findings = analyze_ipa(str(ipa_path))
    ids = {f.check_id for f in findings}
    assert "MOBILE-010" in ids
    assert "MOBILE-011" in ids
    assert "MOBILE-013" in ids


def test_analyze_ipa_clean(tmp_path):
    from vamp_mobile_audit import PRIVACY_KEYS_REQUIRED
    plist = {k: f"We use {k}" for k in PRIVACY_KEYS_REQUIRED}
    ipa_path = tmp_path / "clean.ipa"
    ipa_path.write_bytes(make_ipa(plist))
    findings = analyze_ipa(str(ipa_path))
    assert not any(f.check_id in {"MOBILE-010", "MOBILE-011", "MOBILE-012"} for f in findings)


# ─── Integrate: analyze_apk con fixture sintético ────────────────────────────

def test_analyze_apk_debuggable(tmp_path):
    manifest = _MANIFEST_BASE.format(body="""
      <uses-sdk android:targetSdkVersion="34"/>
      <application android:debuggable="true" android:allowBackup="false"
                   android:usesCleartextTraffic="false">
      </application>
    """)
    apk_path = tmp_path / "debug.apk"
    # Add NSC to avoid MOBILE-009
    apk_path.write_bytes(make_apk(manifest, extra_names=["res/xml/network_security_config.xml"]))
    findings = analyze_apk(str(apk_path))
    ids = {f.check_id for f in findings}
    assert "MOBILE-001" in ids


def test_analyze_apk_exported_component(tmp_path):
    manifest = _MANIFEST_BASE.format(body="""
      <uses-sdk android:targetSdkVersion="34"/>
      <application android:allowBackup="false">
        <activity android:name=".ExposedActivity" android:exported="true"/>
      </application>
    """)
    apk_path = tmp_path / "exported.apk"
    apk_path.write_bytes(make_apk(manifest, extra_names=["res/xml/network_security_config.xml"]))
    findings = analyze_apk(str(apk_path))
    ids = {f.check_id for f in findings}
    assert "MOBILE-004" in ids


# ─── Exit codes ───────────────────────────────────────────────────────────────

def test_main_exit_0_on_clean(tmp_path):
    from vamp_mobile_audit import PRIVACY_KEYS_REQUIRED
    plist = {k: f"We use {k}" for k in PRIVACY_KEYS_REQUIRED}
    ipa_path = tmp_path / "clean.ipa"
    ipa_path.write_bytes(make_ipa(plist))
    code = main([str(ipa_path), "--json", "-", "--quiet"])
    assert code == 0


def test_main_exit_2_on_critical(tmp_path):
    plist = {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
    ipa_path = tmp_path / "critical.ipa"
    ipa_path.write_bytes(make_ipa(plist))
    code = main([str(ipa_path), "--quiet"])
    assert code == 2


# ─── DEX string extractor ────────────────────────────────────────────────────

def test_extract_dex_strings_invalid():
    """Datos inválidos no deben lanzar excepción."""
    result = extract_dex_strings(b"not a dex file")
    assert result == []


def test_extract_dex_strings_empty():
    assert extract_dex_strings(b"") == []


# ─── Finding.from_check helper ───────────────────────────────────────────────

def test_finding_from_check_roundtrip():
    f = Finding.from_check("MOBILE-001", "test description", ["ev1", "ev2"])
    d = f.to_dict()
    assert d["check_id"] == "MOBILE-001"
    assert d["severity"] == "critical"
    assert d["masvs"] == "MASVS-RESILIENCE-2"
    assert d["evidence"] == ["ev1", "ev2"]
