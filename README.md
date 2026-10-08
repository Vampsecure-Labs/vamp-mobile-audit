# vamp-mobile-audit

**OWASP MASVS 2.0 static auditor for APK and IPA files.**  
VampSecure Labs Security Research Division — pure Python, zero external dependencies.

## Features

- **15 MASVS 2.0 checks** covering Android (MOBILE-001–009) and iOS (MOBILE-010–015)
- **Zero external dependencies** — uses only Python standard library (zipfile, struct, plistlib, re…)
- **Pure-Python AXML parser** for binary AndroidManifest.xml (no jadx/apktool required)
- **DEX string extraction** for secrets and weak-crypto pattern detection
- **JSON + HTML reports** suitable for automated pipelines and human review
- **Exit codes** compatible with CI/CD: `2` = CRITICAL, `1` = HIGH/MEDIUM, `0` = clean

## Checks

| ID | Title | Severity | Platform | MASVS |
|----|-------|----------|----------|-------|
| MOBILE-001 | APK debuggable habilitado | critical | android | MASVS-RESILIENCE-2 |
| MOBILE-002 | Backup sin cifrar permitido | high | android | MASVS-STORAGE-2 |
| MOBILE-003 | Tráfico HTTP en claro permitido | high | android | MASVS-NETWORK-1 |
| MOBILE-004 | Componente exportado sin permiso | high | android | MASVS-PLATFORM-1 |
| MOBILE-005 | Secretos hardcodeados en binario | critical | android | MASVS-STORAGE-1 |
| MOBILE-006 | Permisos peligrosos innecesarios | medium | android | MASVS-PLATFORM-2 |
| MOBILE-007 | Algoritmos criptográficos débiles | high | android | MASVS-CRYPTO-1 |
| MOBILE-008 | URLs HTTP en código fuente | medium | android | MASVS-NETWORK-1 |
| MOBILE-009 | Network Security Config ausente | medium | android | MASVS-NETWORK-2 |
| MOBILE-010 | ATS desactivado (NSAllowsArbitraryLoads) | critical | ios | MASVS-NETWORK-1 |
| MOBILE-011 | File sharing habilitado | medium | ios | MASVS-STORAGE-2 |
| MOBILE-012 | Secretos en Info.plist | critical | ios | MASVS-STORAGE-1 |
| MOBILE-013 | URL schemes personalizados expuestos | low | ios | MASVS-PLATFORM-1 |
| MOBILE-014 | Excepciones ATS por dominio | medium | ios | MASVS-NETWORK-1 |
| MOBILE-015 | Descripción de privacidad ausente | medium | ios | MASVS-PRIVACY-1 |

## Installation

```bash
pip install vamp-mobile-audit
```

Or from source:

```bash
git clone https://github.com/Vampsecure-Labs/vamp-mobile-audit
cd vamp-mobile-audit
pip install -e .
```

## Usage

```bash
# Audit an APK
vamp-mobile-audit app.apk

# Audit an IPA
vamp-mobile-audit app.ipa

# JSON report
vamp-mobile-audit app.apk --json report.json

# HTML report
vamp-mobile-audit app.apk --html report.html

# With case metadata
vamp-mobile-audit app.apk --case CASO-2026-001 --analyst "Equipo Red"

# Filter by severity
vamp-mobile-audit app.apk --severity critical high

# Quiet mode (exit code only)
vamp-mobile-audit app.apk --quiet
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings (clean) |
| 1 | HIGH or MEDIUM findings (no CRITICAL) |
| 2 | CRITICAL findings present |

## Sample Output

```
  vamp-mobile-audit v1.0 · auditing app.apk (28.4 MB)
  ──────────────────────────────────────────────────────────────
  [+] APK unpacked · AndroidManifest.xml parsed · DEX strings extracted

  ┌─ CRITICAL ──────────────────────────────────────────────────────────┐
  │  MOBILE-005  Hardcoded secrets in DEX binary                        │
  │  Matches: AWS_SECRET_KEY, API_TOKEN, PRIVATE_KEY (3 patterns)       │
  │  Location: classes.dex                                              │
  │  MASVS: MASVS-STORAGE-1                                            │
  └─────────────────────────────────────────────────────────────────────┘

  [CRITICAL] MOBILE-001  APK compiled with debuggable=true — ADB shell access enabled
  [HIGH]     MOBILE-003  Cleartext HTTP traffic permitted (usesCleartextTraffic=true)
  [HIGH]     MOBILE-004  Exported Activity without permission: com.example.DeepLinkActivity
  [HIGH]     MOBILE-007  Weak cryptography: DES, MD5 detected in classes.dex
  [MEDIUM]   MOBILE-006  Dangerous permissions: RECORD_AUDIO, READ_CONTACTS, SEND_SMS
  [MEDIUM]   MOBILE-008  HTTP URLs in binary: http://api.example.com/v1/data (3 found)
  [MEDIUM]   MOBILE-009  Network Security Config absent — no certificate pinning declared

  ──────────────────────────────────────────────────
  Case: CASO-2026-001 · Analyst: Equipo Red
  Platform: Android · 15 checks run · 8 findings
  CRITICAL: 2 · HIGH: 3 · MEDIUM: 3
```

## Why vamp-mobile-audit vs. MobSF · apkleaks · objection

| Feature | vamp-mobile-audit | MobSF | apkleaks | objection |
|---------|:-----------------:|:-----:|:--------:|:---------:|
| Zero external dependencies (pure Python stdlib) | ✅ | ❌ | ❌ | ❌ |
| APK + IPA in a single tool | ✅ | ✅ | ❌ | ❌ |
| OWASP MASVS 2.0 mapped findings (ID + category) | ✅ | Parcial | ❌ | ❌ |
| Offline binary only (no jadx / apktool / frida) | ✅ | ❌ | ✅ | ❌ |
| Dynamic runtime hooking | ❌ | ❌ | ❌ | ✅ |
| JSON + HTML export ready for client report | ✅ | ✅ | ❌ | ❌ |
| CI/CD exit codes (0/1/2) | ✅ | ❌ | ❌ | ❌ |
| Case metadata (analyst, case ID) per report | ✅ | ❌ | ❌ | ❌ |

- **No setup friction.** MobSF requires Docker, a running server, and a web UI upload step. vamp-mobile-audit runs with `pip install` and a single CLI command — useful in CI/CD pipelines or air-gapped environments.
- **MASVS 2.0 traceability by design.** Every finding references the exact MASVS 2.0 control ID (`MASVS-STORAGE-1`, `MASVS-NETWORK-1`, etc.) so outputs map directly to a formal standard — not just "found a potential issue".
- **Dual platform (Android + iOS) in one binary.** apkleaks handles only APK secrets. objection requires a live device. vamp-mobile-audit runs static analysis on both APK and IPA with the same command-line interface.
- **Audit-ready deliverables.** The `--case` and `--analyst` flags embed engagement metadata into every JSON and HTML report, eliminating manual post-processing before delivery to a client.

## Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| MOBILE-001 | APK debuggable flag set (allows ADB shell attach) | MASVS-RESILIENCE-2 · OWASP MSTG-RESILIENCE-2 | CRITICAL |
| MOBILE-002 | Android backup allowed without encryption (`allowBackup=true`) | MASVS-STORAGE-2 | HIGH |
| MOBILE-003 | Cleartext HTTP traffic permitted (`usesCleartextTraffic=true`) | MASVS-NETWORK-1 · RFC 2818 | HIGH |
| MOBILE-004 | Exported Activity, Service, or Provider without permission guard | MASVS-PLATFORM-1 · CWE-926 | HIGH |
| MOBILE-005 | Hardcoded secrets (API keys, tokens, private keys) in DEX binary | MASVS-STORAGE-1 · CWE-312 | CRITICAL |
| MOBILE-006 | Dangerous permissions requested: RECORD_AUDIO, READ_CONTACTS, SMS | MASVS-PLATFORM-2 | MEDIUM |
| MOBILE-007 | Weak cryptographic algorithms (DES, RC4, MD5) in DEX | MASVS-CRYPTO-1 · CWE-327 | HIGH |
| MOBILE-008 | HTTP URLs hardcoded in binary (unencrypted endpoint references) | MASVS-NETWORK-1 | MEDIUM |
| MOBILE-009 | Network Security Config absent (no certificate pinning declared) | MASVS-NETWORK-2 | MEDIUM |
| MOBILE-010 | ATS disabled: `NSAllowsArbitraryLoads = true` in Info.plist | MASVS-NETWORK-1 · Apple ATS | CRITICAL |
| MOBILE-011 | UIFileSharingEnabled = true (file sharing exposes app sandbox) | MASVS-STORAGE-2 | MEDIUM |
| MOBILE-012 | Secrets or tokens present in Info.plist keys | MASVS-STORAGE-1 · CWE-312 | CRITICAL |
| MOBILE-013 | Custom URL scheme registered (potential deep-link hijacking) | MASVS-PLATFORM-1 · CWE-939 | LOW |
| MOBILE-014 | Per-domain ATS exception (NSExceptionDomains) disables TLS checks | MASVS-NETWORK-1 | MEDIUM |
| MOBILE-015 | Privacy usage description absent for sensitive API (camera, mic…) | MASVS-PRIVACY-1 · Apple guidelines | MEDIUM |

## License

AGPL-3.0-only — see [LICENSE](LICENSE).
