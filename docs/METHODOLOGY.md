# 🔬 PatchStack Security Methodology & Standards Mapping

## 1. Vulnerability Detection Algorithms

### SQL Injection (`SQLInjectionDetector`)
1. **Parameter Discovery**: Extract query parameters and POST parameters.
2. **Error-Based Probing**: Inject SQL single quotes (`'`). Search response body against regex patterns for SQLite, MySQL, PostgreSQL, and Oracle syntax errors.
3. **Boolean-Based Probing**: Compare HTTP response status code and body byte size between TRUE (`1' OR '1'='1`) and FALSE (`1' AND '1'='2`) probes.
4. **Remediation**: Use parameterized queries (`cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`).

### Cross-Site Scripting & Input Validation (`XSSDetector`)
1. **Canary Discovery**: Send unique alphanumeric string (`pstk9a8b7`) to verify parameter reflection.
2. **Context Analysis**: Inspect reflection location (HTML body, attribute value, script block).
3. **Polyglot Verification**: Send HTML tag payload `<pstktag attr="test">` and verify if response reflects unescaped `<` and `>`.
4. **Remediation**: Apply context-aware HTML entity encoding (`html.escape()`).

### Insecure Direct Object References (`IDORAccessControlDetector`)
1. **Multi-Session Probing**: Authenticate as User 101 (`SESSION-USER-101`).
2. **Cross-Account Access**: Request User 102's private object endpoint (`/api/user/102`).
3. **Authorization Check**: If response status code is 200 OK and contains User 102 data, flag IDOR.
4. **Remediation**: Verify `session_user_id == requested_object_id` before returning resource.

### Authentication & Session Security (`AuthSessionDetector`)
1. **Username Enumeration**: Compare response text between invalid user probe (`"User not found"`) vs valid user probe (`"Incorrect password"`).
2. **Predictable Session Tokens**: Inspect sequential token patterns (`SESSION-1001`, `SESSION-1002`).
3. **Rate Limiting / Lockout**: Send 6 consecutive failed logins to test for missing HTTP 429 / lockout.
4. **Cookie Flags**: Verify `HttpOnly`, `Secure`, and `SameSite` flags on authentication cookies.

---

## 2. Standards Cross-Reference Matrix

| Detector | Category | CWE Code | OWASP Top 10 (2021) Category |
| :--- | :--- | :--- | :--- |
| `SQLInjectionDetector` | SQL Injection | **CWE-89** | **A03:2021 - Injection** |
| `XSSDetector` | Reflected / Stored XSS | **CWE-79** | **A03:2021 - Injection** |
| `IDORAccessControlDetector` | IDOR / Broken Access | **CWE-639** | **A01:2021 - Broken Access Control** |
| `AuthSessionDetector` | Username Enumeration | **CWE-203** | **A07:2021 - Identification & Auth Failures** |
| `AuthSessionDetector` | Predictable Session Token | **CWE-330** | **A07:2021 - Identification & Auth Failures** |
| `AuthSessionDetector` | Missing Rate Limiting | **CWE-307** | **A07:2021 - Identification & Auth Failures** |
| `CookieSecurityDetector` | Insecure Cookie Flags | **CWE-614** / **CWE-1004** | **A05:2021 - Security Misconfiguration** |
| `CORSConfigDetector` | Permissive CORS | **CWE-942** | **A05:2021 - Security Misconfiguration** |
| `DangerousMethodsDetector` | Unsafe HTTP Methods | **CWE-16** | **A05:2021 - Security Misconfiguration** |
| `SecurityHeadersDetector` | Missing CSP / HSTS | **CWE-1021** / **CWE-523** | **A05:2021 - Security Misconfiguration** |
| `ServerInfoDisclosureDetector` | Server Version Leak | **CWE-200** | **A05:2021 - Security Misconfiguration** |
