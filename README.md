# vamp-mobile-audit

**OWASP MASVS 2.0 static auditor for APK and IPA files.**  
VampSecure Labs Security Research Division — pure Python, zero external dependencies.

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

OWASP MASVS 2.0 static auditor for APK and IPA files. Pure Python, zero external dependencies.

### Features

- **15 MASVS 2.0 checks** covering Android (MOBILE-001–009) and iOS (MOBILE-010–015)
- **Zero external dependencies** — uses only Python standard library (zipfile, struct, plistlib, re…)
- **Pure-Python AXML parser** for binary AndroidManifest.xml (no jadx/apktool required)
- **DEX string extraction** for secrets and weak-crypto pattern detection
- **JSON + HTML reports** suitable for automated pipelines and human review
- **Exit codes** compatible with CI/CD: `2` = CRITICAL, `1` = HIGH/MEDIUM, `0` = clean

### Checks

| ID | Title | Severity | Platform | MASVS |
|----|-------|----------|----------|-------|
| MOBILE-001 | APK debuggable flag enabled | critical | android | MASVS-RESILIENCE-2 |
| MOBILE-002 | Unencrypted backup allowed | high | android | MASVS-STORAGE-2 |
| MOBILE-003 | Cleartext HTTP traffic permitted | high | android | MASVS-NETWORK-1 |
| MOBILE-004 | Exported component without permission | high | android | MASVS-PLATFORM-1 |
| MOBILE-005 | Hardcoded secrets in binary | critical | android | MASVS-STORAGE-1 |
| MOBILE-006 | Unnecessary dangerous permissions | medium | android | MASVS-PLATFORM-2 |
| MOBILE-007 | Weak cryptographic algorithms | high | android | MASVS-CRYPTO-1 |
| MOBILE-008 | HTTP URLs in source code | medium | android | MASVS-NETWORK-1 |
| MOBILE-009 | Network Security Config absent | medium | android | MASVS-NETWORK-2 |
| MOBILE-010 | ATS disabled (NSAllowsArbitraryLoads) | critical | ios | MASVS-NETWORK-1 |
| MOBILE-011 | File sharing enabled | medium | ios | MASVS-STORAGE-2 |
| MOBILE-012 | Secrets in Info.plist | critical | ios | MASVS-STORAGE-1 |
| MOBILE-013 | Custom URL schemes exposed | low | ios | MASVS-PLATFORM-1 |
| MOBILE-014 | ATS per-domain exceptions | medium | ios | MASVS-NETWORK-1 |
| MOBILE-015 | Privacy usage description absent | medium | ios | MASVS-PRIVACY-1 |

### Installation

```bash
pip install vamp-mobile-audit
```

Or from source:

```bash
git clone https://github.com/Vampsecure-Labs/vamp-mobile-audit
cd vamp-mobile-audit
pip install -e .
```

### Usage

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
vamp-mobile-audit app.apk --case CASE-2026-001 --analyst "Red Team"

# Filter by severity
vamp-mobile-audit app.apk --severity critical high

# Quiet mode (exit code only)
vamp-mobile-audit app.apk --quiet
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings (clean) |
| 1 | HIGH or MEDIUM findings (no CRITICAL) |
| 2 | CRITICAL findings present |

### Sample Output

```
  vamp-mobile-audit v1.1 · auditing app.apk (28.4 MB)
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
  Case: CASE-2026-001 · Analyst: Red Team
  Platform: Android · 15 checks run · 8 findings
  CRITICAL: 2 · HIGH: 3 · MEDIUM: 3
```

### Why vamp-mobile-audit vs. MobSF · apkleaks · objection

| Feature | vamp-mobile-audit | MobSF | apkleaks | objection |
|---------|:-----------------:|:-----:|:--------:|:---------:|
| Zero external dependencies (pure Python stdlib) | ✅ | ❌ | ❌ | ❌ |
| APK + IPA in a single tool | ✅ | ✅ | ❌ | ❌ |
| OWASP MASVS 2.0 mapped findings (ID + category) | ✅ | Partial | ❌ | ❌ |
| Offline binary only (no jadx / apktool / frida) | ✅ | ❌ | ✅ | ❌ |
| Dynamic runtime hooking | ❌ | ❌ | ❌ | ✅ |
| JSON + HTML export ready for client report | ✅ | ✅ | ❌ | ❌ |
| CI/CD exit codes (0/1/2) | ✅ | ❌ | ❌ | ❌ |
| Case metadata (analyst, case ID) per report | ✅ | ❌ | ❌ | ❌ |

- **No setup friction.** MobSF requires Docker, a running server, and a web UI upload step. vamp-mobile-audit runs with `pip install` and a single CLI command — useful in CI/CD pipelines or air-gapped environments.
- **MASVS 2.0 traceability by design.** Every finding references the exact MASVS 2.0 control ID (`MASVS-STORAGE-1`, `MASVS-NETWORK-1`, etc.) so outputs map directly to a formal standard — not just "found a potential issue".
- **Dual platform (Android + iOS) in one binary.** apkleaks handles only APK secrets. objection requires a live device. vamp-mobile-audit runs static analysis on both APK and IPA with the same command-line interface.
- **Audit-ready deliverables.** The `--case` and `--analyst` flags embed engagement metadata into every JSON and HTML report, eliminating manual post-processing before delivery to a client.

### Check Coverage

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

### License

AGPL-3.0-only — see [LICENSE](LICENSE).

### Version History

| Version | Main changes |
|---------|-------------|
| v1.1 | Bilingual README (EN/ES) |
| v1.0 | 15 MASVS 2.0 checks (Android + iOS), pure-Python AXML parser, DEX string extraction |

---

© VampSecure Studios — VampSecure Labs Security Research Division

---
---

<a name="español"></a>
## 🇪🇸 Español

Auditor estático OWASP MASVS 2.0 para ficheros APK e IPA. Python puro, sin dependencias externas.

### Características

- **15 checks MASVS 2.0** que cubren Android (MOBILE-001–009) e iOS (MOBILE-010–015)
- **Sin dependencias externas** — usa únicamente la librería estándar de Python (zipfile, struct, plistlib, re…)
- **Parser AXML en Python puro** para AndroidManifest.xml binario (sin jadx/apktool)
- **Extracción de strings DEX** para detección de secretos y criptografía débil
- **Informes JSON + HTML** aptos para pipelines automatizados y revisión humana
- **Códigos de salida** compatibles con CI/CD: `2` = CRITICAL, `1` = HIGH/MEDIUM, `0` = limpio

### Checks

| ID | Título | Severidad | Plataforma | MASVS |
|----|--------|-----------|------------|-------|
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

### Instalación

```bash
pip install vamp-mobile-audit
```

Desde el código fuente:

```bash
git clone https://github.com/Vampsecure-Labs/vamp-mobile-audit
cd vamp-mobile-audit
pip install -e .
```

### Uso

```bash
# Auditar un APK
vamp-mobile-audit app.apk

# Auditar un IPA
vamp-mobile-audit app.ipa

# Informe JSON
vamp-mobile-audit app.apk --json report.json

# Informe HTML
vamp-mobile-audit app.apk --html report.html

# Con metadatos del caso
vamp-mobile-audit app.apk --case CASO-2026-001 --analyst "Equipo Red"

# Filtrar por severidad
vamp-mobile-audit app.apk --severity critical high

# Modo silencioso (solo código de salida)
vamp-mobile-audit app.apk --quiet
```

### Códigos de salida

| Código | Significado |
|--------|-------------|
| 0 | Sin hallazgos (limpio) |
| 1 | Hallazgos HIGH o MEDIUM (sin CRITICAL) |
| 2 | Hallazgos CRITICAL presentes |

### Por qué vamp-mobile-audit vs. MobSF · apkleaks · objection

| Feature | vamp-mobile-audit | MobSF | apkleaks | objection |
|---------|:-----------------:|:-----:|:--------:|:---------:|
| Sin dependencias externas (stdlib Python puro) | ✅ | ❌ | ❌ | ❌ |
| APK + IPA en una sola herramienta | ✅ | ✅ | ❌ | ❌ |
| Hallazgos mapeados a OWASP MASVS 2.0 (ID + categoría) | ✅ | Parcial | ❌ | ❌ |
| Offline solo binario (sin jadx / apktool / frida) | ✅ | ❌ | ✅ | ❌ |
| Hooking dinámico en runtime | ❌ | ❌ | ❌ | ✅ |
| Exportación JSON + HTML lista para informe de cliente | ✅ | ✅ | ❌ | ❌ |
| Códigos de salida CI/CD (0/1/2) | ✅ | ❌ | ❌ | ❌ |
| Metadatos del caso (analista, ID de caso) en cada informe | ✅ | ❌ | ❌ | ❌ |

### Cobertura de checks

| Check ID | Descripción | Estándar | Severidad |
|----------|-------------|----------|-----------|
| MOBILE-001 | APK debuggable habilitado (permite adjuntar shell ADB) | MASVS-RESILIENCE-2 · OWASP MSTG-RESILIENCE-2 | CRITICAL |
| MOBILE-002 | Backup Android permitido sin cifrado (`allowBackup=true`) | MASVS-STORAGE-2 | HIGH |
| MOBILE-003 | Tráfico HTTP en claro permitido (`usesCleartextTraffic=true`) | MASVS-NETWORK-1 · RFC 2818 | HIGH |
| MOBILE-004 | Activity, Service o Provider exportado sin guardia de permiso | MASVS-PLATFORM-1 · CWE-926 | HIGH |
| MOBILE-005 | Secretos hardcodeados (API keys, tokens, claves privadas) en binario DEX | MASVS-STORAGE-1 · CWE-312 | CRITICAL |
| MOBILE-006 | Permisos peligrosos solicitados: RECORD_AUDIO, READ_CONTACTS, SMS | MASVS-PLATFORM-2 | MEDIUM |
| MOBILE-007 | Algoritmos criptográficos débiles (DES, RC4, MD5) en DEX | MASVS-CRYPTO-1 · CWE-327 | HIGH |
| MOBILE-008 | URLs HTTP hardcodeadas en binario (referencias a endpoints sin cifrar) | MASVS-NETWORK-1 | MEDIUM |
| MOBILE-009 | Network Security Config ausente (sin certificate pinning declarado) | MASVS-NETWORK-2 | MEDIUM |
| MOBILE-010 | ATS desactivado: `NSAllowsArbitraryLoads = true` en Info.plist | MASVS-NETWORK-1 · Apple ATS | CRITICAL |
| MOBILE-011 | UIFileSharingEnabled = true (el file sharing expone el sandbox de la app) | MASVS-STORAGE-2 | MEDIUM |
| MOBILE-012 | Secretos o tokens presentes en claves de Info.plist | MASVS-STORAGE-1 · CWE-312 | CRITICAL |
| MOBILE-013 | URL scheme personalizado registrado (posible deep-link hijacking) | MASVS-PLATFORM-1 · CWE-939 | LOW |
| MOBILE-014 | Excepción ATS por dominio (NSExceptionDomains) desactiva checks TLS | MASVS-NETWORK-1 | MEDIUM |
| MOBILE-015 | Descripción de uso de privacidad ausente para API sensible (cámara, mic…) | MASVS-PRIVACY-1 · Apple guidelines | MEDIUM |

### Licencia

AGPL-3.0-only — ver [LICENSE](LICENSE).

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.1 | README bilingüe (EN/ES) |
| v1.0 | 15 checks MASVS 2.0 (Android + iOS), parser AXML en Python puro, extracción de strings DEX |

---

© VampSecure Studios — VampSecure Labs Security Research Division
