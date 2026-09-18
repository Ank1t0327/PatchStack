# 🛡️ PatchStack Threat Model & Security Framework

## 1. System Boundary & Scope

PatchStack operates as an authorized Web Application Security Assessment Platform scanning web applications over standard HTTP/HTTPS protocols.

```
+-------------------------------------------------------------------+
|                         TRUST BOUNDARY                            |
|                                                                   |
|   +--------------------+               +----------------------+   |
|   | PatchStack Engine  | --(HTTP)----> |  Target Web App      |   |
|   | (Auditor Client)   | <--(Resp)---- |  (Flask Testbed)     |   |
|   +--------------------+               +----------------------+   |
|            |                                      |               |
|            v                                      v               |
|   +--------------------+               +----------------------+   |
|   | SQLite DB & Report |               | In-Memory SQLite DB  |   |
|   | (patchstack.db)    |               | (User/Session Store) |   |
|   +--------------------+               +----------------------+   |
+-------------------------------------------------------------------+
```

## 2. STRIDE Threat Analysis

| Threat Category | Vulnerability Area | Description & Attack Vector | PatchStack Detection & Mitigation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Authentication | Weak session tokens (`SESSION-1001`) allow session hijacking. | `AuthSessionDetector` tests token entropy; mitigated via `secrets.token_urlsafe(32)`. |
| **Tampering** | SQL Injection | SQL single quote injection manipulates database queries. | `SQLInjectionDetector` detects error/boolean differentials; mitigated via Parameterized Queries. |
| **Repudiation** | Logging | Unauthenticated requests executed without audit logging. | `StructuredLogger` records audit events and request telemetry. |
| **Info Disclosure**| XSS / Headers | Unescaped user input reflects scripts; Server header leaks OS/version details. | `XSSDetector` & `ServerInfoDisclosureDetector` identify leaks; mitigated via `html.escape()`. |
| **Denial of Service**| Rate Limiting | Missing brute-force lockout allows infinite login probes. | `AuthSessionDetector` tests rate limits; mitigated via 15-min account lockout after 5 fails. |
| **Elevation of Privilege**| IDOR | User 101 fetches User 102 profile without authorization checks. | `IDORAccessControlDetector` audits cross-account access; mitigated via session ownership checks. |

## 3. Risk Assessment & Scoring Methodology

PatchStack calculates normalized target risk score (0.0 to 10.0) using:

$$\text{Risk Score} = \min\left(10.0, \frac{\sum w_i \times c_i}{1.5}\right)$$

- **Severity Weights ($w_i$)**: Critical = 10.0, High = 7.5, Medium = 4.0, Low = 1.5, Info = 0.5.
- **Confidence Multipliers ($c_i$)**: High = 1.0, Medium = 0.8, Low = 0.5.

## 4. Security Assumptions & Safe Probing Guidelines

1. **Controlled Environment**: Scanning MUST only be executed against targets where explicit written authorization is granted.
2. **Non-Destructive Payloads**: Detectors utilize safe test canary strings (`pstk9a8b7`, `<pstktag>`) and controlled SQL probes (`1'`, `1' OR '1'='1`) without altering database state or deleting records.
