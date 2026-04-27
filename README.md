# XSS Demo Lab

Interactive educational lab for learning Cross-Site Scripting (XSS) — detection, exploitation, and defense.

> **Warning:** This project contains intentionally vulnerable code. Run on `localhost` only. Never deploy vulnerable routes to a public server.

---

## Prerequisites

- Node.js v18+
- npm

## Quick Start

```bash
npm install
npm start
```

Open [http://localhost:3001](http://localhost:3001)

---

## Project Structure

```
XSS/
├── server.js                  # Express server — all API routes
├── public/
│   ├── index.html             # Home — lab overview
│   ├── identify.html          # Step 1: Finding injection points
│   ├── styles.css             # Shared styles
│   ├── challenges.css         # Challenge lab styles
│   ├── session-init.js        # Seeds fake session in localStorage
│   ├── vulnerable/
│   │   ├── reflected.html     # Reflected XSS demo page
│   │   ├── stored.html        # Stored XSS demo page
│   │   ├── dom.html           # DOM-based XSS demo page
│   │   ├── attribute.html     # Attribute context XSS demo page
│   │   └── jscontext.html     # JS context XSS demo page
│   ├── secure/
│   │   ├── reflected.html     # Secure version — Reflected
│   │   ├── stored.html        # Secure version — Stored
│   │   ├── dom.html           # Secure version — DOM
│   │   ├── attribute.html     # Secure version — Attribute
│   │   └── jscontext.html     # Secure version — JS context
│   └── challenges/
│       └── index.html         # Challenge hub (8 challenges)
└── codegraph/                 # Python venv for code-review-graph MCP
```

---

## Learning Path

### Step 1 — Identify Injection Points
**`/identify.html`**

Annotated form showing every type of XSS injection point: text inputs, textareas, URL parameters, hidden fields, `href` attributes, HTTP headers, and DOM sinks. Includes a reconnaissance checklist and input-type summary table. Form submits to `/api/identify` which reflects all values raw so you can inspect the page source.

### Step 2 — Understand Each XSS Type

| Type | Vulnerable Page | Secure Page | API Route |
|------|----------------|-------------|-----------|
| Reflected | `/vulnerable/reflected.html` | `/secure/reflected.html` | `GET /api/search?q=` |
| Stored | `/vulnerable/stored.html` | `/secure/stored.html` | `GET/POST /api/comments` |
| DOM-based | `/vulnerable/dom.html` | `/secure/dom.html` | (client-side only) |
| Attribute Context | `/vulnerable/attribute.html` | `/secure/attribute.html` | `GET /api/profile?color=&username=&website=` |
| JS Context | `/vulnerable/jscontext.html` | `/secure/jscontext.html` | `GET /api/theme?color=` |

Each vulnerable page shows: the root cause, clickable attack payloads, side-by-side vulnerable vs secure code, and the attack flow.

### Step 3 — Challenge Lab
**`/challenges`** — 8 progressive challenges

| # | Title | Difficulty | Key Concept |
|---|-------|-----------|-------------|
| 1 | Basic Reflected XSS | Easy | No filter — raw reflection |
| 2 | Script Tag Filter | Easy | `<script>` stripped — use event handlers |
| 3 | Aggressive Filter Bypass | Medium | `on*` + `javascript:` stripped — creative bypass |
| 4 | Attribute Context | Medium | Unquoted attribute — break out with `"` |
| 5 | JS String Context | Medium | Inside `<script>` string literal — break with `"` |
| 6 | User-Agent Header | Hard | Non-form vector — requires curl or Burp |
| 7 | Stored XSS | Hard | Payload persists for all visitors |
| 8 | href Injection | Hard | `escapeHtml()` is the wrong fix for URL context |
| S | The Secure Form | Expert | All defenses active — try to break it |

---

## API Routes

```
GET  /api/identify          Reflects all query params raw (Step 1 demo)
GET  /api/search?q=         Vulnerable reflected XSS
GET  /api/search/safe?q=    Secure version
GET  /api/comments          Vulnerable stored XSS board
POST /api/comments          Post to vulnerable board
GET  /api/comments/safe     Secure board
POST /api/comments/safe     Post to secure board
GET  /api/profile?...       Vulnerable attribute context
GET  /api/profile/safe?...  Secure attribute context
GET  /api/theme?color=      Vulnerable JS context
GET  /api/theme/safe?color= Secure JS context
GET  /api/challenges/1-8    Individual challenge pages
GET  /api/challenges/secure The unbreakable secure form
```

---

## Defense Reference

| Injection Context | Correct Defense |
|-------------------|----------------|
| HTML body content | `escapeHtml(value)` |
| HTML attribute (always quote) | `escapeHtml(value)` |
| URL attribute (`href`, `src`, `action`) | `escapeHtml(safeUrl(value))` |
| Inside `<script>` block | `safeJsonForScript(value)` |
| URL query parameter | `encodeURIComponent(value)` |
| Rich text (user HTML) | `DOMPurify.sanitize(value)` |

Helper functions are implemented in `server.js`:
- `escapeHtml(str)` — encodes `& < > " '`
- `safeUrl(url)` — allowlists `http:` / `https:` schemes only
- `safeJsonForScript(value)` — `JSON.stringify()` + encodes `< > /` to prevent `</script>` injection

---

## Simulated Session

On page load, `session-init.js` seeds fake data into `localStorage`:

```
sessionToken, csrfToken, userId, username, email, role, lastLogin
```

XSS payloads on vulnerable pages can steal this data — demonstrating real-world cookie/token theft without affecting any real accounts.

---

## Tools Used in This Lab

| Tool | Use |
|------|-----|
| Browser DevTools | Edit hidden fields, inspect DOM, view source |
| `curl` | Send custom HTTP headers (Challenge 6) |
| Burp Suite | Intercept and modify any request |

---

## Port

Default: **3001**. Override with `PORT` env var:

```bash
PORT=8080 npm start
```
