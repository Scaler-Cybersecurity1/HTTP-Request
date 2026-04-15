# Scaler — HTTP Protocol Security Lab: Guided Walkthrough

> This guide walks you through the **approach** for each scenario without revealing the answers. Use it to build your methodology — not to skip the analysis.

---

## Scenario 01: CL.TE Desync

**What you're looking at:** A captured HTTP request from a passive network tap between a CDN proxy and an origin server. Both servers handle the same request, but they disagree on how to determine where the request body ends.

### Step 1 — Understand the Two Parsing Modes

Look at the request headers carefully. There are **two headers** that both define how the body length should be calculated. The proxy trusts one, the origin trusts the other. Identify which server uses which header from the Target Configuration panel.

### Step 2 — Walk Through the Proxy's Perspective

The proxy reads the body using its preferred header. Count the exact number of bytes it considers as the body. From the proxy's point of view, how many HTTP requests exist in this stream? The answer should be one — everything is part of a single POST.

### Step 3 — Walk Through the Origin's Perspective

Now switch to the origin's parsing logic. It uses the other header to read the body. Under chunked transfer encoding, the body ends at a specific termination signal. Find that termination point in the raw request.

### Step 4 — Find What's Left in the Buffer

After the origin finishes reading the body (which ends much earlier than the proxy thinks), there are leftover bytes sitting in the TCP connection buffer. The origin will parse those leftover bytes as a **brand new, independent request**. Read those bytes — that's your smuggled request.

### Step 5 — Extract the Path

The smuggled request has a method, a path, and query parameters. The answer is the full path (including the query string) of this second request that only the origin sees.

**Where to look:** Raw Request tab, Hex Dump tab (highlighted bytes show the smuggled portion), Parsed Headers tab (Conflict Analysis pane).

---

## Scenario 02: TE.CL Cache Poison

**What you're looking at:** A crafted request sent to a reverse proxy + backend stack where the proxy and backend disagree on body parsing — but in the **opposite direction** from Scenario 01. A cache layer (Varnish) sits in front, caching GET responses.

### Step 1 — Identify Which Server Uses Which Header

This is a TE.CL desync — the reverse of CL.TE. Read the Infrastructure Map to confirm: the proxy uses Transfer-Encoding, the backend uses Content-Length. This is critical because it changes which server "sees too much" vs "sees too little."

### Step 2 — Follow the Proxy's Parse

The proxy reads the body as chunked. Look at the chunk sizes in the raw payload. The first chunk has a hex size — convert it to decimal to understand how many bytes the proxy reads. The terminal chunk (`0`) signals the end. From the proxy's view, this is one complete POST request.

### Step 3 — Follow the Backend's Parse

The backend ignores Transfer-Encoding and uses `Content-Length`. Look at the Content-Length value — it's very small. Count exactly that many bytes from the start of the body. That tiny slice is all the backend considers as the POST body.

### Step 4 — Identify the Remainder

Everything after those few bytes is still in the TCP buffer. The backend's HTTP parser will attempt to read the next request from this buffer. Look at what comes immediately after the Content-Length boundary — you should see a fully formed HTTP request line.

### Step 5 — Determine Method + Path

The smuggled request has a clear HTTP method and path. That's your answer: the method and path that the backend parses from the leftover buffer.

**Where to look:** Raw Payload tab, Backend View (Apache) tab — the split pane shows exactly what Apache reads as body vs what remains. The Varnish Cache Log confirms what got cached.

---

## Scenario 03: SSRF Attack Chain

**What you're looking at:** Incident response logs from a breached AWS-hosted SaaS platform. The attacker used a webhook feature to make the server fetch URLs of their choosing (SSRF). The logs show a sequence of requests that progressively dig deeper into the cloud infrastructure.

### Step 1 — Read the Application Logs Chronologically

Open the `webhook-service.log` panel. The attacker made several requests in sequence, each one building on information from the previous response. Read the `Fetching URL:` entries in order — they tell you exactly what the attacker was targeting.

### Step 2 — Identify the Target of the First Probe

The attacker's first SSRF request targets a specific IP address. This isn't a random internal host — it's a well-known cloud service endpoint. The IP address appears in every single SSRF request in the logs. Note it.

### Step 3 — Understand the Enumeration Pattern

The attacker follows a specific path hierarchy on that IP:
1. First request: the root metadata path
2. Second request: navigates to a specific metadata category
3. Third request: retrieves the actual sensitive data

This is a classic three-step enumeration pattern for a specific cloud service.

### Step 4 — Cross-Reference with CloudTrail

The CloudTrail logs show what the attacker did **after** obtaining credentials from the SSRF. The `GetCallerIdentity` call confirms what role was compromised. The subsequent API calls show the full blast radius.

### Step 5 — Submit the Pivot Point

The question asks for the IP address that made the entire chain possible. It's the common target across all the SSRF requests — the endpoint that serves instance metadata including credentials.

**Where to look:** The `webhook-service.log` panel — every SSRF URL contains the target IP. The SSRF Response panel confirms what was returned.

---

## Scenario 04: XSS to Session Hijack

**What you're looking at:** Forensic artifacts from a multi-stage intrusion — a database extract showing a stored XSS payload, a recovered JavaScript file from an S3 bucket, a browser network capture, and server access logs showing the session being reused from a different IP.

### Step 1 — Trace the XSS Payload

Start with the database artifact (task #4721 description). The XSS payload uses an `<img>` tag with an `onerror` handler that loads an external script. Note the URL of the external script — this is the **hosting** location, but it's not where the stolen data goes.

### Step 2 — Read the External Script

Switch to the recovered `t.js` source. This is the actual exfiltration code. Read it line by line:
- What data does it collect?
- How does it encode the data?
- Where does it send the data?

The script constructs a URL and makes a request to it. The **domain** in that URL is where stolen data is sent.

### Step 3 — Distinguish Hosting from Exfiltration

There are two different external domains in this attack:
1. Where the malicious script is **hosted** (the S3 bucket URL in the XSS payload)
2. Where the stolen data is **sent** (the URL inside the script's `Image().src`)

These are different domains. The question asks for the exfiltration destination, not the script host.

### Step 4 — Verify with the Network Capture

Switch to the Network Capture tab. This shows the actual HTTP request that left the admin's browser when the script executed. The `Host` header and the request URL confirm the exfiltration domain. The decoded base64 payload shows exactly what was stolen.

### Step 5 — Confirm the Chain in Access Logs

The access logs show the timeline: the admin views the task, the outbound request fires, and then minutes later the same session ID appears from a completely different IP address. The `[IP MISMATCH]` alerts confirm session hijacking. The subsequent `POST /admin/users/create` entries show the attacker creating persistence.

**Where to look:** The `t.js Source` tab for the exfiltration URL, the Network Capture tab for confirmation. Don't confuse the S3 hosting domain with the data collection domain.

---

## General Tips

- **Read every tab.** The split panes, alternate views, and log panels contain different perspectives on the same data. Switching between them often makes the answer obvious.
- **Follow the timestamps.** The logs are in chronological order. The sequence of events tells the story.
- **Look at what's highlighted.** In hex views, highlighted bytes mark the interesting regions. In log panels, color-coded severity levels (WARN, CRIT, ALERT) point to anomalies.
- **Think like the parser.** For smuggling challenges, mentally step through each server's parsing algorithm byte by byte. The disagreement between parsers is the entire vulnerability.
- **Think like the attacker.** For chain challenges, each step produces output that enables the next step. Follow the information flow.
