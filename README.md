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

## License

AGPL-3.0-only — see [LICENSE](LICENSE).
