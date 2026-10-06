#!/usr/bin/env python3
# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp-mobile-audit — Auditor OWASP MASVS 2.0 para APK (Android) e IPA (iOS).
VampSecure Labs (Vampsecure Studios).

Analiza estáticamente ficheros APK/IPA sin ejecutar código ni requerir
jadx/apktool. Cubre 15 checks MOBILE-001..015 del OWASP MASVS 2.0.

Ejemplos:
  vamp-mobile-audit app.apk
  vamp-mobile-audit app.ipa --json hallazgos.json
  vamp-mobile-audit app.apk --html informe.html --case "AUDIT-2026-001"
  vamp-mobile-audit app.apk --severity critical high --json -

Exit codes:
  2 = hallazgos CRITICAL
  1 = hallazgos HIGH/MEDIUM (sin CRITICAL)
  0 = limpio
"""
import argparse
import hashlib
import html as _html
import json
import os
import re
import struct
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ─── Catálogo de checks ──────────────────────────────────────────────────────

CHECKS: Dict[str, Dict] = {
    "MOBILE-001": {"title": "APK debuggable habilitado",              "severity": "critical", "masvs": "MASVS-RESILIENCE-2", "platform": "android"},
    "MOBILE-002": {"title": "APK backup sin restricción",             "severity": "high",     "masvs": "MASVS-STORAGE-2",   "platform": "android"},
    "MOBILE-003": {"title": "Tráfico cleartext permitido (APK)",      "severity": "high",     "masvs": "MASVS-NETWORK-1",   "platform": "android"},
    "MOBILE-004": {"title": "Component exportado sin permiso",        "severity": "high",     "masvs": "MASVS-PLATFORM-1",  "platform": "android"},
    "MOBILE-005": {"title": "Secretos hardcodeados (APK)",            "severity": "critical", "masvs": "MASVS-STORAGE-1",   "platform": "android"},
    "MOBILE-006": {"title": "Permisos peligrosos declarados",         "severity": "medium",   "masvs": "MASVS-PLATFORM-1",  "platform": "android"},
    "MOBILE-007": {"title": "Criptografía débil en DEX",              "severity": "high",     "masvs": "MASVS-CRYPTO-1",    "platform": "android"},
    "MOBILE-008": {"title": "URLs HTTP en strings DEX",               "severity": "medium",   "masvs": "MASVS-NETWORK-1",   "platform": "android"},
    "MOBILE-009": {"title": "Sin network_security_config",            "severity": "medium",   "masvs": "MASVS-NETWORK-2",   "platform": "android"},
    "MOBILE-010": {"title": "NSAllowsArbitraryLoads habilitado",      "severity": "critical", "masvs": "MASVS-NETWORK-1",   "platform": "ios"},
    "MOBILE-011": {"title": "UIFileSharingEnabled habilitado",        "severity": "high",     "masvs": "MASVS-STORAGE-2",   "platform": "ios"},
    "MOBILE-012": {"title": "Secretos hardcodeados (Info.plist)",     "severity": "critical", "masvs": "MASVS-STORAGE-1",   "platform": "ios"},
    "MOBILE-013": {"title": "URL scheme personalizado expuesto",      "severity": "medium",   "masvs": "MASVS-PLATFORM-1",  "platform": "ios"},
    "MOBILE-014": {"title": "Excepciones ATS por dominio",            "severity": "medium",   "masvs": "MASVS-NETWORK-1",   "platform": "ios"},
    "MOBILE-015": {"title": "Descripción de privacidad ausente",      "severity": "medium",   "masvs": "MASVS-PRIVACY-1",   "platform": "ios"},
}

SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})'), "API key"),
    (re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9+/]{16,})'), "AWS credential"),
    (re.compile(r'(?i)(password|passwd|secret|token)\s*[=:]\s*["\']([^"\']{8,})["\']'), "hardcoded credential"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Google API key"),
    (re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}'), "GitHub token"),
    (re.compile(r'sk-[A-Za-z0-9]{40,}'), "secret key"),
    (re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'), "Slack token"),
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "private key"),
]

DANGEROUS_PERMISSIONS = {
    "READ_CONTACTS", "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO", "CAMERA",
    "READ_CALL_LOG", "WRITE_CALL_LOG",
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS",
    "READ_PHONE_STATE", "CALL_PHONE",
    "BODY_SENSORS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "GET_ACCOUNTS",
    "USE_BIOMETRIC", "USE_FINGERPRINT",
}

WEAK_CRYPTO_PATTERNS = ["DES/", "DESede/", "/ECB/", "RC4", "Blowfish/", "ARC4", "MD5withRSA"]

PRIVACY_KEYS_REQUIRED = [
    "NSCameraUsageDescription",
    "NSMicrophoneUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSContactsUsageDescription",
    "NSPhotoLibraryUsageDescription",
]

PRIVACY_KEYS_OPTIONAL = [
    "NSFaceIDUsageDescription",
    "NSHealthShareUsageDescription",
    "NSBluetoothAlwaysUsageDescription",
    "NSLocationAlwaysUsageDescription",
]


# ─── Finding ────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    masvs: str
    platform: str
    description: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "masvs": self.masvs,
            "platform": self.platform,
            "description": self.description,
            "evidence": self.evidence,
        }

    @classmethod
    def from_check(cls, cid: str, description: str, evidence: Optional[List[str]] = None) -> "Finding":
        c = CHECKS[cid]
        return cls(
            check_id=cid,
            title=c["title"],
            severity=c["severity"],
            masvs=c["masvs"],
            platform=c["platform"],
            description=description,
            evidence=evidence or [],
        )


# ─── Android Binary XML (AXML) parser ───────────────────────────────────────

class AXMLParser:
    """Minimal pure-Python parser para AndroidManifest.xml en formato binario."""

    _STRING_POOL  = 0x0001
    _START_ELEM   = 0x0102
    _END_ELEM     = 0x0103
    _START_NS     = 0x0100
    _END_NS       = 0x0101

    _T_STRING  = 0x03
    _T_BOOL    = 0x12
    _T_INT_DEC = 0x10
    _T_INT_HEX = 0x11

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._strings: List[str] = []
        self.elements: List[Tuple[str, Dict[str, str]]] = []
        try:
            self._parse()
        except Exception:
            pass

    def _u32(self, pos: int) -> int:
        return struct.unpack_from("<I", self._data, pos)[0]

    def _i32(self, pos: int) -> int:
        return struct.unpack_from("<i", self._data, pos)[0]

    def _u16(self, pos: int) -> int:
        return struct.unpack_from("<H", self._data, pos)[0]

    def _parse(self) -> None:
        pos = 8  # skip file chunk header (8 bytes)
        while pos + 8 <= len(self._data):
            chunk_type = self._u16(pos)
            chunk_size = self._u32(pos + 4)
            if chunk_size < 8:
                break
            if chunk_type == self._STRING_POOL:
                self._parse_string_pool(pos)
            elif chunk_type == self._START_ELEM:
                self._parse_start_element(pos)
            pos += chunk_size

    def _parse_string_pool(self, base: int) -> None:
        # ResStringPool_header: chunk_header(8) + stringCount(4) + styleCount(4)
        #                      + flags(4) + stringsStart(4) + stylesStart(4)
        string_count = self._u32(base + 8)
        flags        = self._u32(base + 16)
        strings_start = self._u32(base + 20)
        is_utf8 = bool(flags & 0x100)
        offsets_base = base + 28
        data_base = base + strings_start
        for i in range(min(string_count, 20_000)):
            offset = self._u32(offsets_base + i * 4)
            self._strings.append(self._read_str(data_base + offset, is_utf8))

    def _read_str(self, pos: int, is_utf8: bool) -> str:
        try:
            d = self._data
            if is_utf8:
                cl = d[pos]
                pos += 2 if cl & 0x80 else 1
                bl = d[pos]
                pos += 2 if bl & 0x80 else 1
                bl &= 0x7F
                return d[pos:pos + bl].decode("utf-8", errors="replace")
            else:
                length = self._u16(pos)
                pos += 2
                return d[pos:pos + length * 2].decode("utf-16-le", errors="replace")
        except (IndexError, struct.error):
            return ""

    def _s(self, idx: int) -> str:
        return self._strings[idx] if 0 <= idx < len(self._strings) else ""

    def _parse_start_element(self, base: int) -> None:
        # ResXMLTree_node (16 bytes) + ResXMLTree_attrExt (20 bytes)
        # node: chunk_header(8) + lineNumber(4) + comment(4)
        # attrExt: ns(4) + name(4) + attrStart(2) + attrSize(2) + attrCount(2) + ...
        name_idx   = self._i32(base + 20)
        attr_start = self._u16(base + 24)  # offset from start of attrExt
        attr_size  = self._u16(base + 26)
        attr_count = self._u16(base + 28)
        tag = self._s(name_idx)
        attrs: Dict[str, str] = {}
        # attrExt starts at base+16; attrs at base+16+attr_start
        attr_base = base + 16 + attr_start
        for i in range(attr_count):
            off = attr_base + i * attr_size
            a_name = self._i32(off + 4)
            a_type = self._data[off + 15]  # Res_value.dataType at +12+3
            a_data = self._i32(off + 16)
            name = self._s(a_name)
            if not name:
                continue
            if a_type == self._T_STRING:
                value = self._s(a_data)
            elif a_type == self._T_BOOL:
                value = "true" if a_data else "false"
            elif a_type == self._T_INT_HEX:
                value = hex(a_data & 0xFFFFFFFF)
            else:
                value = str(a_data)
            attrs[name] = value
        self.elements.append((tag, attrs))


# ─── DEX string extractor ────────────────────────────────────────────────────

def _read_uleb128(data: bytes, pos: int) -> Tuple[int, int]:
    result = shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7

def extract_dex_strings(data: bytes, limit: int = 50_000) -> List[str]:
    strings: List[str] = []
    try:
        if not data[:4] == b"dex\n":
            return strings
        string_ids_size = struct.unpack_from("<I", data, 56)[0]
        string_ids_off  = struct.unpack_from("<I", data, 60)[0]
        for i in range(min(string_ids_size, limit)):
            str_data_off = struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
            _, pos = _read_uleb128(data, str_data_off)
            end = data.index(b"\x00", pos)
            strings.append(data[pos:end].decode("utf-8", errors="replace"))
    except (struct.error, ValueError, IndexError):
        pass
    return strings


# ─── APK check functions (operan sobre datos ya parseados) ──────────────────

def check_debuggable(elements: List[Tuple[str, Dict]]) -> Optional[Finding]:
    for tag, attrs in elements:
        if tag == "application" and attrs.get("debuggable") == "true":
            return Finding.from_check(
                "MOBILE-001",
                "La app declara android:debuggable=\"true\". Permite adjuntar un depurador "
                "en producción, extraer memoria y bypassear certificate pinning con Frida/objection.",
                ["AndroidManifest.xml: android:debuggable=\"true\""],
            )
    return None


def check_backup(elements: List[Tuple[str, Dict]]) -> Optional[Finding]:
    for tag, attrs in elements:
        if tag == "application":
            val = attrs.get("allowBackup", "true")
            if val != "false":
                return Finding.from_check(
                    "MOBILE-002",
                    "android:allowBackup no está explícitamente desactivado (valor actual: "
                    f"\"{val}\"). Cualquier usuario con adb puede extraer datos de la app "
                    "sin root mediante `adb backup`.",
                    [f"AndroidManifest.xml: android:allowBackup=\"{val}\""],
                )
    return None


def check_cleartext(elements: List[Tuple[str, Dict]], apk_names: List[str]) -> Optional[Finding]:
    for tag, attrs in elements:
        if tag == "application" and attrs.get("usesCleartextTraffic") == "true":
            return Finding.from_check(
                "MOBILE-003",
                "La app permite tráfico HTTP en claro (android:usesCleartextTraffic=\"true\"). "
                "Credenciales y datos de sesión pueden interceptarse en redes locales.",
                ["AndroidManifest.xml: android:usesCleartextTraffic=\"true\""],
            )
    # También se activa si el networkSecurityConfig no existe y targetSdk < 28
    for tag, attrs in elements:
        if tag == "uses-sdk":
            target = attrs.get("targetSdkVersion", "")
            try:
                if int(target, 0) < 28:
                    has_nsc = any("network_security_config" in n for n in apk_names)
                    if not has_nsc:
                        return Finding.from_check(
                            "MOBILE-003",
                            f"targetSdkVersion={target} sin network_security_config. "
                            "En API < 28 el cleartext está permitido por defecto.",
                            [f"AndroidManifest.xml: android:targetSdkVersion=\"{target}\""],
                        )
            except (ValueError, TypeError):
                pass
    return None


def check_exported_components(elements: List[Tuple[str, Dict]]) -> Optional[Finding]:
    exposed = []
    component_tags = {"activity", "service", "receiver", "provider"}
    for tag, attrs in elements:
        if tag not in component_tags:
            continue
        exported = attrs.get("exported", "")
        permission = attrs.get("permission", "")
        name = attrs.get("name", tag)
        if exported == "true" and not permission:
            exposed.append(f"{tag} '{name}' exportado sin permiso")
    if exposed:
        return Finding.from_check(
            "MOBILE-004",
            f"{len(exposed)} componente(s) exportado(s) sin declarar android:permission. "
            "Cualquier app del dispositivo puede invocarlos.",
            exposed[:5],
        )
    return None


def check_secrets_in_strings(strings: List[str]) -> Optional[Finding]:
    hits: List[str] = []
    for s in strings:
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(s):
                trimmed = s[:120] + "…" if len(s) > 120 else s
                hits.append(f"[{label}] {trimmed}")
                break
    if hits:
        return Finding.from_check(
            "MOBILE-005",
            f"Se detectaron {len(hits)} posible(s) secreto(s) hardcodeado(s) en strings DEX/recursos.",
            hits[:5],
        )
    return None


def check_dangerous_permissions(elements: List[Tuple[str, Dict]]) -> Optional[Finding]:
    found: List[str] = []
    for tag, attrs in elements:
        if tag == "uses-permission":
            name = attrs.get("name", "")
            short = name.split(".")[-1]
            if short in DANGEROUS_PERMISSIONS:
                found.append(name)
    if found:
        return Finding.from_check(
            "MOBILE-006",
            f"La app solicita {len(found)} permiso(s) peligroso(s). "
            "Verificar que todos son estrictamente necesarios y que el principio "
            "de mínimo privilegio se respeta.",
            found[:8],
        )
    return None


def check_weak_crypto(strings: List[str]) -> Optional[Finding]:
    hits: List[str] = []
    for s in strings:
        for pattern in WEAK_CRYPTO_PATTERNS:
            if pattern in s:
                hits.append(f"DEX string: \"{s[:80]}\"")
                break
    if hits:
        return Finding.from_check(
            "MOBILE-007",
            f"Referencias a criptografía débil o insegura en {len(hits)} string(s) DEX. "
            "DES, DESede, RC4, Blowfish y modo ECB no deben usarse en apps modernas.",
            hits[:5],
        )
    return None


def check_http_urls(strings: List[str]) -> Optional[Finding]:
    _http = re.compile(r"^https?://(?!localhost|127\.|10\.|192\.168\.|0\.0\.0\.0)[^\s]{8,}")
    hits = [s for s in strings if _http.match(s) and s.startswith("http://")]
    if hits:
        return Finding.from_check(
            "MOBILE-008",
            f"Se encontraron {len(hits)} URL(s) HTTP en claro en strings DEX. "
            "Las comunicaciones deben usar HTTPS.",
            [h[:100] for h in hits[:5]],
        )
    return None


def check_no_network_security_config(apk_names: List[str]) -> Optional[Finding]:
    has_nsc = any(
        "res/xml/network_security_config" in n or "network_security_config.xml" in n
        for n in apk_names
    )
    if not has_nsc:
        return Finding.from_check(
            "MOBILE-009",
            "No se encontró network_security_config.xml. Sin este fichero no es posible "
            "implementar certificate pinning ni restringir dominios permitidos para cleartext.",
            ["res/xml/network_security_config.xml: ausente"],
        )
    return None


# ─── IPA check functions ────────────────────────────────────────────────────

def check_ats_arbitrary_loads(plist: dict) -> Optional[Finding]:
    ats = plist.get("NSAppTransportSecurity", {})
    if ats.get("NSAllowsArbitraryLoads") is True:
        return Finding.from_check(
            "MOBILE-010",
            "NSAllowsArbitraryLoads = true desactiva App Transport Security completamente. "
            "La app puede comunicarse con cualquier servidor HTTP sin validación TLS.",
            ["Info.plist → NSAppTransportSecurity.NSAllowsArbitraryLoads = true"],
        )
    return None


def check_file_sharing(plist: dict) -> Optional[Finding]:
    if plist.get("UIFileSharingEnabled") is True:
        return Finding.from_check(
            "MOBILE-011",
            "UIFileSharingEnabled = true permite acceder al sandbox de la app desde iTunes/Finder. "
            "Expone ficheros de datos locales sin autenticación.",
            ["Info.plist → UIFileSharingEnabled = true"],
        )
    return None


def check_secrets_in_plist(plist: dict) -> Optional[Finding]:
    hits: List[str] = []
    def _scan(obj, path: str) -> None:
        if isinstance(obj, str):
            for pat, label in SECRET_PATTERNS:
                if pat.search(obj):
                    trimmed = obj[:100] + "…" if len(obj) > 100 else obj
                    hits.append(f"[{label}] {path}: {trimmed}")
                    break
        elif isinstance(obj, dict):
            for k, v in obj.items():
                _scan(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                _scan(v, f"{path}[{i}]")
    _scan(plist, "Info.plist")
    if hits:
        return Finding.from_check(
            "MOBILE-012",
            f"Se detectaron {len(hits)} posible(s) secreto(s) hardcodeado(s) en Info.plist.",
            hits[:5],
        )
    return None


def check_url_schemes(plist: dict) -> Optional[Finding]:
    schemes: List[str] = []
    for url_type in plist.get("CFBundleURLTypes", []):
        for scheme in url_type.get("CFBundleURLSchemes", []):
            if scheme.lower() not in {"http", "https", "mailto", "tel"}:
                schemes.append(scheme)
    if schemes:
        return Finding.from_check(
            "MOBILE-013",
            f"La app registra {len(schemes)} URL scheme(s) personalizados. "
            "Los URL schemes no tienen autenticación de origen: cualquier app puede invocarlos. "
            "Verificar que los parámetros se validan y no se ejecuta código arbitrario.",
            [f"CFBundleURLScheme: {s}" for s in schemes[:5]],
        )
    return None


def check_ats_domain_exceptions(plist: dict) -> Optional[Finding]:
    ats = plist.get("NSAppTransportSecurity", {})
    exceptions = ats.get("NSExceptionDomains", {})
    insecure = []
    for domain, cfg in exceptions.items():
        if cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
            insecure.append(domain)
        if cfg.get("NSExceptionMinimumTLSVersion", "") in ("TLSv1.0", "TLSv1.1"):
            insecure.append(f"{domain} (TLS obsoleto)")
    if insecure:
        return Finding.from_check(
            "MOBILE-014",
            f"{len(insecure)} dominio(s) con excepciones ATS que reducen la seguridad TLS.",
            [f"NSExceptionDomains: {d}" for d in insecure[:5]],
        )
    return None


def check_privacy_descriptions(plist: dict) -> Optional[Finding]:
    missing = [k for k in PRIVACY_KEYS_REQUIRED if k not in plist]
    if missing:
        return Finding.from_check(
            "MOBILE-015",
            f"Faltan {len(missing)} clave(s) de descripción de privacidad requeridas "
            "por App Store Review. Sin ellas la app puede ser rechazada o crashear en iOS 14+.",
            [f"Falta: {k}" for k in missing],
        )
    return None


# ─── Analizadores de alto nivel ─────────────────────────────────────────────

def _apk_entries(zf: zipfile.ZipFile) -> List[str]:
    return [i.filename for i in zf.infolist()]


def analyze_apk(path: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = _apk_entries(zf)

            # Parse AndroidManifest.xml
            elements: List[Tuple[str, Dict]] = []
            try:
                manifest_data = zf.read("AndroidManifest.xml")
                # Try binary AXML first
                if manifest_data[:4] == b"\x03\x00\x08\x00"[:4] or manifest_data[0:2] == b"\x03\x00":
                    elements = AXMLParser(manifest_data).elements
                elif manifest_data.lstrip()[:5] == b"<?xml":
                    # Plain XML fallback (testing / older tools)
                    elements = _parse_plain_xml_manifest(manifest_data)
            except (KeyError, Exception):
                pass

            # Gather DEX strings
            dex_strings: List[str] = []
            for name in names:
                if name.endswith(".dex"):
                    try:
                        dex_strings.extend(extract_dex_strings(zf.read(name)))
                    except Exception:
                        pass

            # Also scan resources for secrets
            resource_strings: List[str] = []
            for name in names:
                if name.endswith(".xml") and "res/" in name:
                    try:
                        raw = zf.read(name)
                        resource_strings.append(raw.decode("latin-1", errors="replace"))
                    except Exception:
                        pass

            all_strings = dex_strings + resource_strings

            # Run checks
            for fn in [
                lambda: check_debuggable(elements),
                lambda: check_backup(elements),
                lambda: check_cleartext(elements, names),
                lambda: check_exported_components(elements),
                lambda: check_secrets_in_strings(all_strings),
                lambda: check_dangerous_permissions(elements),
                lambda: check_weak_crypto(dex_strings),
                lambda: check_http_urls(dex_strings),
                lambda: check_no_network_security_config(names),
            ]:
                result = fn()
                if result:
                    findings.append(result)

    except zipfile.BadZipFile:
        pass
    return findings


def _parse_plain_xml_manifest(data: bytes) -> List[Tuple[str, Dict[str, str]]]:
    """Fallback: parse plain-text XML manifest (for tests / older tools)."""
    import xml.etree.ElementTree as ET
    elements = []
    try:
        root = ET.fromstring(data)
        NS = "http://schemas.android.com/apk/res/android"
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            attrs: Dict[str, str] = {}
            for k, v in elem.attrib.items():
                short_k = k.replace(f"{{{NS}}}", "").split("}")[-1]
                attrs[short_k] = v
            elements.append((tag, attrs))
    except Exception:
        pass
    return elements


def analyze_ipa(path: str) -> List[Finding]:
    import plistlib
    findings: List[Finding] = []
    plist: dict = {}
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = [i.filename for i in zf.infolist()]
            # Info.plist está en Payload/<AppName>.app/Info.plist
            plist_names = [n for n in names if n.endswith("/Info.plist") and "Payload/" in n]
            if not plist_names:
                # Try root level (test fixtures)
                plist_names = [n for n in names if n == "Info.plist"]
            if plist_names:
                raw = zf.read(plist_names[0])
                plist = plistlib.loads(raw)
    except (zipfile.BadZipFile, Exception):
        return findings

    for fn in [
        lambda: check_ats_arbitrary_loads(plist),
        lambda: check_file_sharing(plist),
        lambda: check_secrets_in_plist(plist),
        lambda: check_url_schemes(plist),
        lambda: check_ats_domain_exceptions(plist),
        lambda: check_privacy_descriptions(plist),
    ]:
        result = fn()
        if result:
            findings.append(result)

    return findings


def _detect_platform(path: str) -> str:
    p = path.lower()
    if p.endswith(".apk") or p.endswith(".aab"):
        return "android"
    if p.endswith(".ipa"):
        return "ios"
    # Try to detect by content
    try:
        with zipfile.ZipFile(path) as zf:
            names = [i.filename for i in zf.infolist()]
            if "AndroidManifest.xml" in names:
                return "android"
            if any("Info.plist" in n for n in names):
                return "ios"
    except Exception:
        pass
    return "unknown"


# ─── Salida ──────────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_SEV_COLOR = {
    "critical": "#dc143c",
    "high":     "#f59e0b",
    "medium":   "#00c6e0",
    "low":      "#22c55e",
    "info":     "#94a3b8",
}


def build_report(
    target: str,
    platform: str,
    findings: List[Finding],
    case_id: str = "",
    analyst: str = "",
) -> dict:
    sha256 = ""
    try:
        h = hashlib.sha256()
        with open(target, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        sha256 = h.hexdigest()
    except Exception:
        pass

    summary: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1
    summary["total"] = len(findings)

    return {
        "target": os.path.basename(target),
        "platform": platform,
        "sha256": sha256,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "analyst": analyst,
        "findings": [f.to_dict() for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.severity, 0), reverse=True)],
        "summary": summary,
    }


def render_html(report: dict) -> str:
    target = _html.escape(report["target"])
    platform = report["platform"]
    ts = report["timestamp"][:19].replace("T", " ") + " UTC"
    case_id = _html.escape(report.get("case_id") or "")
    analyst = _html.escape(report.get("analyst") or "VampSecure Labs")
    s = report["summary"]
    findings = report["findings"]

    sev_pill = {
        "critical": '<span style="background:#dc143c22;color:#dc143c;border:1px solid #dc143c55;font-size:10px;font-family:monospace;padding:2px 7px;border-radius:3px;font-weight:700">CRITICAL</span>',
        "high":     '<span style="background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b55;font-size:10px;font-family:monospace;padding:2px 7px;border-radius:3px;font-weight:700">HIGH</span>',
        "medium":   '<span style="background:#00c6e022;color:#00c6e0;border:1px solid #00c6e055;font-size:10px;font-family:monospace;padding:2px 7px;border-radius:3px;font-weight:700">MEDIUM</span>',
        "low":      '<span style="background:#22c55e22;color:#22c55e;border:1px solid #22c55e55;font-size:10px;font-family:monospace;padding:2px 7px;border-radius:3px;font-weight:700">LOW</span>',
    }

    rows = []
    for f in findings:
        ev = "".join(f"<li>{_html.escape(e)}</li>" for e in f.get("evidence", []))
        rows.append(f"""
<div style="background:#0d1326;border:1px solid #1a2540;border-left:4px solid {_SEV_COLOR.get(f['severity'],'#4b6080')};border-radius:0 6px 6px 0;padding:14px 18px;margin-bottom:10px">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap">
    <span style="font-family:monospace;font-size:11px;font-weight:700;color:#e2e8f0">{_html.escape(f['check_id'])}</span>
    {sev_pill.get(f['severity'],'')}
    <span style="font-size:12px;font-weight:600;color:#e2e8f0">{_html.escape(f['title'])}</span>
    <span style="font-family:monospace;font-size:9px;color:#4b6080;margin-left:auto">{_html.escape(f['masvs'])}</span>
  </div>
  <p style="font-size:12px;color:#94a3b8;margin:0 0 8px">{_html.escape(f['description'])}</p>
  {"<ul style='font-family:monospace;font-size:11px;color:#64748b;padding-left:16px;margin:0'>" + ev + "</ul>" if ev else ""}
</div>""")

    findings_html = "\n".join(rows) if rows else '<p style="color:#22c55e;font-family:monospace">✔ Sin hallazgos</p>'

    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vamp-mobile-audit — {target}</title>
<style>
body{{background:#07091b;color:#e2e8f0;font-family:'Inter',system-ui,sans-serif;font-size:14px;margin:0;padding:24px}}
h1{{font-size:22px;font-weight:700;color:#fff;margin:0 0 4px}}
.sub{{font-family:monospace;font-size:11px;color:#4b6080;letter-spacing:.08em;text-transform:uppercase;margin-bottom:28px}}
.meta{{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:24px}}
.kpi{{background:#0d1326;border:1px solid #1a2540;border-radius:6px;padding:12px 16px;min-width:100px}}
.kv{{font-family:monospace;font-size:22px;font-weight:700}}
.kl{{font-size:10px;color:#4b6080;text-transform:uppercase;letter-spacing:.07em;margin-top:2px}}
.rc{{font-family:monospace;font-size:11px;color:#dc143c}} .ra{{font-family:monospace;font-size:11px;color:#f59e0b}}
.rm{{font-family:monospace;font-size:11px;color:#00c6e0}} .rg{{font-family:monospace;font-size:11px;color:#22c55e}}
</style>
</head>
<body>
<h1>vamp-mobile-audit</h1>
<div class="sub">VampSecure Labs · OWASP MASVS 2.0 · {platform.upper()}</div>
<div class="meta">
  <div class="kpi"><div class="kv" style="color:#dc143c">{s['critical']}</div><div class="kl">Critical</div></div>
  <div class="kpi"><div class="kv" style="color:#f59e0b">{s['high']}</div><div class="kl">High</div></div>
  <div class="kpi"><div class="kv" style="color:#00c6e0">{s['medium']}</div><div class="kl">Medium</div></div>
  <div class="kpi"><div class="kv" style="color:#94a3b8">{s['total']}</div><div class="kl">Total</div></div>
</div>
<p style="font-family:monospace;font-size:11px;color:#4b6080">
  Target: <span style="color:#e2e8f0">{target}</span> · SHA-256: <span style="color:#64748b">{report['sha256'][:16]}…</span><br>
  {('Case: ' + case_id + ' · ') if case_id else ''}Analyst: {analyst} · {ts}
</p>
<h2 style="font-size:14px;font-family:monospace;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8;border-bottom:1px solid #1a2540;padding-bottom:8px;margin:24px 0 14px">
  Hallazgos ({len(findings)})
</h2>
{findings_html}
<p style="font-family:monospace;font-size:10px;color:#2a3a58;margin-top:32px;border-top:1px solid #1a2540;padding-top:12px">
  © VampSecure Studios — VampSecure Labs Security Research Division · vamp-mobile-audit · AGPL-3.0-only
</p>
</body>
</html>"""


# ─── CLI ─────────────────────────────────────────────────────────────────────

def _exit_code(findings: List[Finding]) -> int:
    severities = {f.severity for f in findings}
    if "critical" in severities:
        return 2
    if severities & {"high", "medium", "low"}:
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vamp-mobile-audit",
        description="Auditor OWASP MASVS 2.0 para APK (Android) e IPA (iOS). "
                    "Análisis estático sin jadx/apktool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Fichero .apk, .aab o .ipa a auditar")
    parser.add_argument("--json", metavar="FILE", help="Guardar hallazgos en JSON (- para stdout)")
    parser.add_argument("--html", metavar="FILE", help="Guardar informe HTML")
    parser.add_argument("--severity", nargs="+", choices=["critical", "high", "medium", "low"],
                        help="Filtrar salida a estas severidades")
    parser.add_argument("--case", metavar="ID", default="", help="ID del caso/engagement")
    parser.add_argument("--analyst", metavar="NAME", default="", help="Nombre del analista")
    parser.add_argument("--quiet", "-q", action="store_true", help="Sin salida a stderr")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.target):
        print(f"[ERROR] Fichero no encontrado: {args.target}", file=sys.stderr)
        return 2

    platform = _detect_platform(args.target)
    if platform == "android":
        findings = analyze_apk(args.target)
    elif platform == "ios":
        findings = analyze_ipa(args.target)
    else:
        print("[ERROR] Formato no reconocido (se esperaba .apk/.aab/.ipa)", file=sys.stderr)
        return 2

    if args.severity:
        findings = [f for f in findings if f.severity in args.severity]

    report = build_report(args.target, platform, findings, args.case, args.analyst)

    if args.json:
        out = json.dumps(report, indent=2, ensure_ascii=False)
        if args.json == "-":
            print(out)
        else:
            Path(args.json).write_text(out, encoding="utf-8")

    if args.html:
        Path(args.html).write_text(render_html(report), encoding="utf-8")

    if not args.quiet:
        s = report["summary"]
        print(f"vamp-mobile-audit · {os.path.basename(args.target)} · {platform.upper()}", file=sys.stderr)
        print(f"  Critical={s['critical']}  High={s['high']}  Medium={s['medium']}  Total={s['total']}", file=sys.stderr)
        for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.severity, 0), reverse=True):
            print(f"  [{f.severity.upper():8}] {f.check_id}: {f.title}", file=sys.stderr)
            for ev in f.evidence[:2]:
                print(f"             → {ev}", file=sys.stderr)

    if not args.json and not args.html:
        print(json.dumps(report, indent=2, ensure_ascii=False))

    return _exit_code(findings)


def main_entry() -> None:
    sys.exit(main())


if __name__ == "__main__":
    main_entry()
