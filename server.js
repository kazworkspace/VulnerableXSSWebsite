const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const vulnerableComments = [];
const secureComments = [];

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// For embedding values inside <script> blocks.
// JSON.stringify alone is not enough — it does NOT encode < > /
// so </script> in a value would close the script tag prematurely.
function safeJsonForScript(value) {
  return JSON.stringify(value)
    .replace(/</g,  '\\u003c')
    .replace(/>/g,  '\\u003e')
    .replace(/\//g, '\\u002f');
}

function safeUrl(url) {
  try {
    const parsed = new URL(url);
    if (['http:', 'https:'].includes(parsed.protocol)) return url;
    return '#blocked';
  } catch {
    if (url.startsWith('/') && !url.startsWith('//')) return url;
    return '#blocked';
  }
}

// Applied to all secure routes as defense-in-depth.
// Note: 'unsafe-inline' is needed here because these demo pages use inline <script>.
// In production you would use nonces or hashes instead.
const SECURE_CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';";

function buildPage(title, badgeType, content, counterpartUrl = null) {
  const isVuln     = badgeType === 'VULNERABLE';
  const badgeColor = isVuln ? '#dc2626' : '#16a34a';
  const badgeBg    = isVuln ? '#fef2f2' : '#f0fdf4';
  const switchLabel = isVuln ? 'View Secure Version →' : '← View Vulnerable Version';
  const switchClass = isVuln ? 'switch-btn switch-to-secure' : 'switch-btn switch-to-vuln';
  const switchBtn   = counterpartUrl
    ? `<a href="${counterpartUrl}" class="${switchClass}">${switchLabel}</a>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} — XSS Demo</title>
  <link rel="stylesheet" href="/styles.css">
  <script src="/session-init.js"></script>
</head>
<body>
  <nav class="topnav">
    <a href="/" class="nav-home">&#8962; Home</a>
    <span class="badge" style="background:${badgeBg};color:${badgeColor};border:1.5px solid ${badgeColor}">${badgeType}</span>
    ${switchBtn}
  </nav>
  <main class="container">
    ${content}
  </main>
</body>
</html>`;
}

// ─────────────────────────────────────────────
// 1. REFLECTED XSS
// ─────────────────────────────────────────────
app.get('/api/search', (req, res) => {
  const q = req.query.q || '';
  const html = buildPage('Reflected XSS — Vulnerable', 'VULNERABLE', `
    <h1>Search Results</h1>
    <p class="vuln-note">You searched for: <span class="highlight">${q}</span></p>
    <div class="result-box">
      <p>No results found for <strong>${q}</strong>.</p>
    </div>
    <a href="/vulnerable/reflected.html" class="btn btn-back">← Back to Demo</a>
  `, '/secure/reflected.html');
  res.set('Content-Type', 'text/html');
  res.send(html);
});

app.get('/api/search/safe', (req, res) => {
  const q    = req.query.q || '';
  const safe = escapeHtml(q);
  const html = buildPage('Reflected XSS — Secure', 'SECURE', `
    <h1>Search Results</h1>
    <p class="secure-note">You searched for: <span class="highlight">${safe}</span></p>
    <div class="result-box">
      <p>No results found for <strong>${safe}</strong>.</p>
    </div>
    <a href="/secure/reflected.html" class="btn btn-back">← Back to Demo</a>
  `, '/vulnerable/reflected.html');
  res.set('Content-Type', 'text/html');
  res.set('Content-Security-Policy', SECURE_CSP);
  res.send(html);
});

// ─────────────────────────────────────────────
// 2. STORED XSS
// ─────────────────────────────────────────────
app.get('/api/comments', (req, res) => {
  const commentList = vulnerableComments.map(c => `
    <div class="comment-card">
      <div class="comment-author">${c.author}</div>
      <div class="comment-body">${c.body}</div>
      <div class="comment-time">${c.time}</div>
    </div>
  `).join('') || '<p class="empty">No comments yet — post a payload above.</p>';

  const html = buildPage('Stored XSS — Vulnerable', 'VULNERABLE', `
    <h1>Comment Board</h1>
    <div class="board-banner vuln-banner">
      &#9888; Raw board — comments are stored and rendered with no sanitization. Any script executes for every visitor.
    </div>
    <form method="POST" action="/api/comments" class="comment-form">
      <input type="text" name="author" placeholder="Your name" required>
      <textarea name="body" rows="4" placeholder="Write a comment or paste an XSS payload..." required></textarea>
      <button type="submit" class="btn btn-vuln">Post Comment</button>
    </form>
    <div class="comments-section">
      <h2>Comments (${vulnerableComments.length})</h2>
      ${commentList}
    </div>
    <a href="/vulnerable/stored.html" class="btn btn-back">← Back to Demo</a>
  `, '/api/comments/safe');
  res.set('Content-Type', 'text/html');
  res.send(html);
});

app.post('/api/comments', (req, res) => {
  const { author, body } = req.body;
  vulnerableComments.push({ author: author || 'Anonymous', body: body || '', time: new Date().toLocaleString() });
  res.redirect('/api/comments');
});

app.get('/api/comments/safe', (req, res) => {
  const commentList = secureComments.map(c => `
    <div class="comment-card">
      <div class="comment-author">${escapeHtml(c.author)}</div>
      <div class="comment-body">${escapeHtml(c.body)}</div>
      <div class="comment-time">${escapeHtml(c.time)}</div>
    </div>
  `).join('') || '<p class="empty">No comments yet — post a payload to see it defanged.</p>';

  const html = buildPage('Stored XSS — Secure', 'SECURE', `
    <h1>Comment Board</h1>
    <div class="board-banner secure-banner">
      &#10003; Secure board — every field is HTML-escaped at render time. Scripts display as literal text.
    </div>
    <form method="POST" action="/api/comments/safe" class="comment-form">
      <input type="text" name="author" placeholder="Your name" required>
      <textarea name="body" rows="4" placeholder="Write a comment or paste an XSS payload..." required></textarea>
      <button type="submit" class="btn btn-secure">Post Comment</button>
    </form>
    <div class="comments-section">
      <h2>Comments (${secureComments.length})</h2>
      ${commentList}
    </div>
    <a href="/secure/stored.html" class="btn btn-back">← Back to Demo</a>
  `, '/api/comments');
  res.set('Content-Type', 'text/html');
  res.set('Content-Security-Policy', SECURE_CSP);
  res.send(html);
});

app.post('/api/comments/safe', (req, res) => {
  const { author, body } = req.body;
  secureComments.push({ author: author || 'Anonymous', body: body || '', time: new Date().toLocaleString() });
  res.redirect('/api/comments/safe');
});

// ─────────────────────────────────────────────
// 3. ATTRIBUTE CONTEXT XSS
// ─────────────────────────────────────────────
app.get('/api/profile', (req, res) => {
  const color    = req.query.color    || 'lightblue';
  const username = req.query.username || 'Alice';
  const website  = req.query.website  || 'https://example.com';
  const toolbar  = req.query.toolbar  || '#toolbar';

  const html = buildPage('Attribute XSS — Vulnerable', 'VULNERABLE', `
    <h1>User Profile Card</h1>

    <div class="attr-scenario">
      <div class="scenario-label vuln">Case A — Unquoted Attribute</div>
      <p class="scenario-desc">
        <code>color</code> injected without quotes: <code>&lt;div style="background:COLOR"&gt;</code><br>
        Payload: <code>red" onmouseover="alert(1)</code> — closes the attribute, injects event handler.
      </p>
      <div class="profile-card" style="background:${color}">
        <strong>Background:</strong> ${color}
      </div>
      <p class="payload-hint">&#128161; Hover the card after submitting the payload.</p>
    </div>

    <div class="attr-scenario">
      <div class="scenario-label vuln">Case B — Quoted Attribute Breakout</div>
      <p class="scenario-desc">
        <code>username</code> inside quotes but not escaped: <code>&lt;input value="USERNAME"&gt;</code><br>
        Payload: <code>" autofocus onfocus="alert(1)</code> — the <code>"</code> closes the attribute.
      </p>
      <div class="profile-card">
        <label>Username field:</label>
        <input type="text" value="${username}" style="width:100%;margin-top:6px">
      </div>
      <p class="payload-hint">&#128161; Input auto-focuses on page load when the payload is active.</p>
    </div>

    <div class="attr-scenario">
      <div class="scenario-label vuln">Case C — href javascript: Injection</div>
      <p class="scenario-desc">
        <code>website</code> placed in <code>href</code> with no scheme validation.<br>
        <code>javascript:alert(1)</code> has <strong>no HTML special chars</strong> — <code>escapeHtml()</code> passes it unchanged.
      </p>
      <div class="profile-card">
        <strong>Website:</strong> <a href="${website}" style="color:#2563eb">Visit website</a>
        <br><small style="color:#9ca3af">href value: <code>${website}</code></small>
      </div>
      <p class="payload-hint">&#128161; Click "Visit website" to trigger.</p>
    </div>

    <div class="attr-scenario">
      <div class="scenario-label vuln">Case D — Unquoted data-* Attribute</div>
      <p class="scenario-desc">
        <code>toolbar</code> injected into an unquoted <code>data-toolbar</code> attribute.<br>
        A space ends the attribute value — everything after becomes new attributes.
      </p>
      <div class="profile-card">
        <table data-toolbar=${toolbar} style="width:100%;border-collapse:collapse">
          <tr><th style="text-align:left;padding:6px;border-bottom:1px solid #e5e7eb">data-toolbar value</th></tr>
          <tr><td style="padding:6px;font-family:monospace;font-size:.85rem">${toolbar}</td></tr>
        </table>
        <small style="color:#9ca3af">Rendered: <code>&lt;table data-toolbar=${toolbar}&gt;</code></small>
      </div>
      <p class="payload-hint">&#128161; Hover the table after submitting — event handler fires.</p>
    </div>

    <a href="/vulnerable/attribute.html" class="btn btn-back">← Back to Demo</a>
  `, '/api/profile/safe');
  res.set('Content-Type', 'text/html');
  res.send(html);
});

app.get('/api/profile/safe', (req, res) => {
  const color    = req.query.color    || 'lightblue';
  const username = req.query.username || 'Alice';
  const website  = req.query.website  || 'https://example.com';
  const toolbar  = req.query.toolbar  || '#toolbar';

  const safeColor    = escapeHtml(color);
  const safeUsername = escapeHtml(username);
  const safeWebsite  = escapeHtml(safeUrl(website));
  const safeToolbar  = escapeHtml(toolbar);

  const html = buildPage('Attribute XSS — Secure', 'SECURE', `
    <h1>User Profile Card</h1>

    <div class="attr-scenario">
      <div class="scenario-label secure">Case A — Fixed: Quote + escapeHtml()</div>
      <p class="scenario-desc">
        Attribute is quoted and value is escaped. Spaces in payload can't start a new attribute.
        <code>"</code> → <code>&amp;quot;</code> — cannot close the attribute.
      </p>
      <div class="profile-card" style="background:${safeColor}">
        <strong>Background:</strong> ${safeColor}
      </div>
      <p class="payload-hint secure-hint">&#10003; Payload displays as inert text.</p>
    </div>

    <div class="attr-scenario">
      <div class="scenario-label secure">Case B — Fixed: escapeHtml() encodes &quot;</div>
      <p class="scenario-desc">
        <code>escapeHtml()</code> converts <code>"</code> → <code>&amp;quot;</code>.
        The payload's quote is trapped inside the value — no new attribute can be injected.
      </p>
      <div class="profile-card">
        <label>Username field:</label>
        <input type="text" value="${safeUsername}" style="width:100%;margin-top:6px">
      </div>
      <p class="payload-hint secure-hint">&#10003; <code>"</code> becomes <code>&amp;quot;</code> — attribute never breaks.</p>
    </div>

    <div class="attr-scenario">
      <div class="scenario-label secure">Case C — Fixed: URL allowlist + escapeHtml()</div>
      <p class="scenario-desc">
        <code>safeUrl()</code> checks scheme first — only <code>http:</code>/<code>https:</code> allowed.
        Then <code>escapeHtml()</code> encodes any remaining HTML special chars.
      </p>
      <div class="profile-card">
        <strong>Website:</strong> <a href="${safeWebsite}" target="_blank" style="color:#16a34a">Visit website</a>
        <br><small style="color:#9ca3af">href value: <code>${safeWebsite}</code></small>
      </div>
      <p class="payload-hint secure-hint">&#10003; <code>javascript:...</code> → href becomes <code>#blocked</code>.</p>
    </div>

    <div class="attr-scenario">
      <div class="scenario-label secure">Case D — Fixed: Quote + escapeHtml() on data-* attribute</div>
      <p class="scenario-desc">
        Attribute is now quoted and value is HTML-escaped.<br>
        <code>data-toolbar="${safeToolbar}"</code> — space inside the quoted value cannot start a new attribute.
      </p>
      <div class="profile-card">
        <table data-toolbar="${safeToolbar}" style="width:100%;border-collapse:collapse">
          <tr><th style="text-align:left;padding:6px;border-bottom:1px solid #e5e7eb">data-toolbar value</th></tr>
          <tr><td style="padding:6px;font-family:monospace;font-size:.85rem">${safeToolbar}</td></tr>
        </table>
        <small style="color:#9ca3af">Rendered: <code>&lt;table data-toolbar="${safeToolbar}"&gt;</code></small>
      </div>
      <p class="payload-hint secure-hint">&#10003; Space trapped inside quotes — no new attribute injected.</p>
    </div>

    <a href="/secure/attribute.html" class="btn btn-back">← Back to Demo</a>
  `, '/api/profile');
  res.set('Content-Type', 'text/html');
  res.set('Content-Security-Policy', SECURE_CSP);
  res.send(html);
});

// ─────────────────────────────────────────────
// 4. JS CONTEXT XSS
// Input lands inside a <script> block — escapeHtml() is the WRONG tool.
// Correct fix: JSON.stringify() + encode < > / to prevent </script> injection.
// ─────────────────────────────────────────────
app.get('/api/theme', (req, res) => {
  const color = req.query.color || 'lightblue';

  // VULNERABLE: raw string interpolation inside a JS string literal.
  // Payload: lightblue"; alert(document.cookie);//
  // Result:  var bgColor = "lightblue"; alert(document.cookie);//";
  //          The " closes the string — code after it executes.
  //
  // Also vulnerable to </script> injection:
  // Payload: lightblue</script><script>alert(1)//
  // HTML parser closes the script tag at </script>, opening a new one.
  const html = buildPage('JS Context XSS — Vulnerable', 'VULNERABLE', `
    <h1>Theme Configurator</h1>
    <p style="color:#6b7280;margin-bottom:20px">
      Sets a background color from the URL parameter. The value is embedded directly
      inside a <code>&lt;script&gt;</code> block with no encoding.
    </p>

    <div id="preview" class="theme-preview">Theme Preview Area</div>

    <div class="attr-scenario" style="margin-top:20px">
      <div class="scenario-label vuln">Injection Point — &lt;script&gt; String Literal</div>
      <p class="scenario-desc">
        Server renders: <code>var bgColor = "<strong>${color}</strong>";</code><br><br>
        <strong>Attack 1 — String breakout:</strong>
        Payload <code>"; alert(document.cookie);//</code> closes the string,
        then executes arbitrary JS.<br><br>
        <strong>Attack 2 — Script tag close:</strong>
        Payload <code>&lt;/script&gt;&lt;script&gt;alert(1)//</code>
        causes the HTML parser to close the script block early.
      </p>
      <p class="payload-hint">Both attacks work because no encoding is applied.</p>
    </div>

    <a href="/vulnerable/jscontext.html" class="btn btn-back">← Back to Demo</a>

    <script>
      // ❌ VULNERABLE: raw user input injected into a JS string literal
      var bgColor = "${color}";
      document.getElementById('preview').style.background = bgColor;
    </script>
  `, '/secure/jscontext.html');
  res.set('Content-Type', 'text/html');
  res.send(html);
});

app.get('/api/theme/safe', (req, res) => {
  const color = req.query.color || 'lightblue';

  // SECURE: JSON.stringify() properly quotes and escapes for JS string context.
  // Additionally encode < > / so </script> cannot close the script tag.
  // JSON.stringify("lightblue\"; alert(1);//") = "\"lightblue\\\"; alert(1);\\/\\/\""
  // After our extra encoding: < → <  > → >  / → /
  const safeColor = safeJsonForScript(color);

  const html = buildPage('JS Context XSS — Secure', 'SECURE', `
    <h1>Theme Configurator</h1>
    <p style="color:#6b7280;margin-bottom:20px">
      Same page — color is processed with <code>safeJsonForScript()</code> before insertion.
      Try the same payloads — they stay trapped in the string.
    </p>

    <div id="preview" class="theme-preview">Theme Preview Area</div>

    <div class="attr-scenario" style="margin-top:20px">
      <div class="scenario-label secure">Fix Applied — safeJsonForScript()</div>
      <p class="scenario-desc">
        Server renders: <code>var bgColor = ${safeColor};</code><br><br>
        <strong>Fix for Attack 1:</strong> <code>JSON.stringify()</code> escapes <code>"</code> as <code>\"</code>
        — the payload's quote cannot close the string.<br><br>
        <strong>Fix for Attack 2:</strong> Extra encoding replaces
        <code>&lt;</code> → <code><</code>, <code>&gt;</code> → <code>></code>,
        <code>/</code> → <code>/</code> — HTML parser never sees <code>&lt;/script&gt;</code>.
      </p>
      <p class="payload-hint secure-hint">&#10003; All payloads render as inert string values.</p>
    </div>

    <a href="/secure/jscontext.html" class="btn btn-back">← Back to Demo</a>

    <script>
      // ✅ SECURE: safeJsonForScript() = JSON.stringify() + encode < > /
      // The value is a valid JS string literal — quotes and special chars are escaped.
      var bgColor = ${safeColor};
      document.getElementById('preview').style.background = bgColor;
    </script>
  `, '/vulnerable/jscontext.html');
  res.set('Content-Type', 'text/html');
  res.set('Content-Security-Policy', SECURE_CSP);
  res.send(html);
});

// Serve challenge hub at /challenges (static file is at /challenges/index.html)
app.get('/challenges', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'challenges', 'index.html'));
});

// ─────────────────────────────────────────────
// IDENTIFY PAGE — reflects all inputs raw (vulnerable)
// Shows learners exactly where their input lands in the HTML
// ─────────────────────────────────────────────
app.get('/api/identify', (req, res) => {
  const search   = req.query.search   || '';
  const fullname = req.query.fullname || '';
  const username = req.query.username || '';
  const email    = req.query.email    || '';
  const website  = req.query.website  || '';
  const bio      = req.query.bio      || '';
  const theme    = req.query.theme    || 'light';
  const redirect = req.query.redirect || '/dashboard';
  const ua       = req.headers['user-agent'] || '';

  function row(label, value, context, note) {
    const hasInput = value !== '';
    const cellStyle = hasInput
      ? 'background:#fef9c3;font-family:monospace;font-size:.85rem;padding:10px 14px;word-break:break-all'
      : 'font-family:monospace;font-size:.85rem;padding:10px 14px;color:#9ca3af';
    return `<tr style="border-bottom:1px solid #f3f4f6">
      <td style="padding:10px 14px;font-weight:600;font-size:.85rem;white-space:nowrap">${escapeHtml(label)}</td>
      <td style="${cellStyle}">${hasInput ? value : '(empty)'}</td>
      <td style="padding:10px 14px;font-size:.82rem;color:#6b7280">${escapeHtml(context)}</td>
      <td style="padding:10px 14px;font-size:.82rem;color:#6b7280">${note}</td>
    </tr>`;
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Identify — Server Response</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <nav class="topnav">
    <a href="/identify.html" class="nav-home">&#8592; Back to Identify Page</a>
    <span class="badge" style="background:#fef2f2;color:#dc2626;border:1.5px solid #dc2626">VULNERABLE — raw reflection</span>
  </nav>
  <main class="container">
    <h1 style="font-size:1.6rem;font-weight:800;margin-bottom:8px">Server Response — Injection Point Map</h1>
    <p style="color:#6b7280;font-size:.9rem;margin-bottom:20px">
      Each value below is reflected <strong>raw</strong> into this page. Highlighted cells contain your input.
      Right-click → View Page Source to see exactly where each value lands in the HTML.
    </p>

    <div class="callout warn" style="margin-bottom:20px">
      <strong>&#9888; What to do:</strong> Press <kbd>Ctrl+U</kbd> (or right-click → View Page Source).
      Search (<kbd>Ctrl+F</kbd>) for your test value. The context around it tells you what payload to use.
    </div>

    <!-- Reflected in body: search -->
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:20px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)">
      <p style="font-size:.8rem;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">HTML Body Reflection</p>
      <p style="font-size:.95rem">Showing results for: <strong>${search}</strong></p>
      <p style="font-size:.95rem;margin-top:8px">Welcome back, <strong>${fullname}</strong>! Logged in as <strong>${username}</strong>.</p>
      <p style="font-size:.875rem;color:#6b7280;margin-top:6px">Confirmation sent to: <strong>${email}</strong></p>
    </div>

    <!-- Attribute reflection -->
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:20px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)">
      <p style="font-size:.8rem;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Attribute + URL Reflection</p>
      <input type="text" value="${username}" style="width:100%;padding:8px 12px;border:1px solid #e5e7eb;border-radius:6px;margin-bottom:10px;font-family:monospace;font-size:.85rem" readonly>
      <p style="font-size:.875rem">Your website: <a href="${website}" style="color:#2563eb">${website || '(none)'}</a></p>
      <p style="font-size:.8rem;color:#9ca3af;margin-top:4px">href value: <code style="font-family:monospace">${website}</code></p>
    </div>

    <!-- JS context reflection -->
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:20px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)">
      <p style="font-size:.8rem;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">JS Context Reflection</p>
      <p style="font-size:.875rem;color:#6b7280;margin-bottom:8px">Theme and redirect land inside a script block:</p>
      <pre style="background:#1e293b;color:#7dd3fc;padding:14px;border-radius:6px;font-size:.8rem;overflow-x:auto"><code>var theme    = "${theme}";
var redirect = "${redirect}";</code></pre>
    </div>

    <!-- Stored bio -->
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:20px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)">
      <p style="font-size:.8rem;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Stored Content (Bio) — rendered raw</p>
      <div style="border:1px dashed #e5e7eb;border-radius:6px;padding:14px;min-height:60px;font-size:.9rem">${bio || '<span style="color:#9ca3af">(empty bio)</span>'}</div>
    </div>

    <!-- Input map table -->
    <p style="font-weight:700;font-size:.85rem;color:#6b7280;text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px">All Received Inputs</p>
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:28px;overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;font-size:.85rem">
        <thead>
          <tr style="background:#f9fafb;border-bottom:2px solid #e5e7eb">
            <th style="text-align:left;padding:10px 14px;color:#6b7280;font-weight:700">Field</th>
            <th style="text-align:left;padding:10px 14px;color:#6b7280;font-weight:700">Raw Value (reflected)</th>
            <th style="text-align:left;padding:10px 14px;color:#6b7280;font-weight:700">Context in HTML</th>
            <th style="text-align:left;padding:10px 14px;color:#6b7280;font-weight:700">XSS Type</th>
          </tr>
        </thead>
        <tbody>
          ${row('search',   search,   'HTML body — "Results for: VALUE"',           'Reflected')}
          ${row('fullname', fullname, 'HTML body — "Welcome back, VALUE"',          'Reflected')}
          ${row('username', username, 'HTML body + input value="" attribute',        'Reflected / Stored')}
          ${row('email',    email,    'HTML body — "Confirmation sent to: VALUE"',  'Reflected')}
          ${row('website',  website,  'href attribute — <a href="VALUE">',           'URL/href injection')}
          ${row('bio',      bio,      'HTML body — rendered raw for all visitors',   'Stored')}
          ${row('theme',    theme,    'JS string literal — var theme = "VALUE"',     'JS context')}
          ${row('redirect', redirect, 'JS string literal — var redirect = "VALUE"',  'JS context / Open redirect')}
          ${row('User-Agent', ua,     'HTTP header — logged, may appear in admin UI','Reflected (non-form)')}
        </tbody>
      </table>
    </div>

    <a href="/identify.html" class="btn btn-back">&#8592; Back to Identify Page</a>
  </main>

  <script>
    var theme    = "${theme}";
    var redirect = "${redirect}";
  </script>
</body>
</html>`;

  res.set('Content-Type', 'text/html');
  res.send(html);
});

// ─────────────────────────────────────────────
// CHALLENGE SYSTEM
// ─────────────────────────────────────────────

function buildChallengePage(num, title, difficulty, filterDesc, bodyHtml, hints) {
  const diffColor = { Easy: '#16a34a', Medium: '#d97706', Hard: '#dc2626', Expert: '#7c3aed' }[difficulty] || '#6b7280';
  const diffBg    = { Easy: '#f0fdf4', Medium: '#fffbeb', Hard: '#fef2f2', Expert: '#f5f3ff' }[difficulty] || '#f9fafb';

  const hintItems = hints.map((h, i) => `
    <details class="hint-item">
      <summary>Hint ${i + 1}</summary>
      <p>${h}</p>
    </details>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Challenge ${num}: ${title}</title>
  <link rel="stylesheet" href="/styles.css">
  <link rel="stylesheet" href="/challenges.css">
</head>
<body>
  <nav class="topnav">
    <a href="/challenges" class="nav-home">&#8962; Challenges</a>
    <span class="ch-num-badge">#${num}</span>
    <span class="badge" style="background:${diffBg};color:${diffColor};border:1.5px solid ${diffColor}">${difficulty}</span>
  </nav>

  <div class="win-banner" id="winBanner" style="display:none">
    <div class="win-inner">
      <span class="win-icon">&#127881;</span>
      <div>
        <strong>Challenge Solved!</strong>
        <p>XSS executed — <code>alert()</code> intercepted. Well done.</p>
      </div>
      <a href="/challenges" class="btn btn-secure" style="margin-left:auto">Next Challenge</a>
    </div>
  </div>

  <main class="container">
    <div class="ch-header">
      <div class="ch-meta">
        <span class="ch-num-large">${num}</span>
        <div>
          <h1>${title}</h1>
          <span class="ch-difficulty" style="color:${diffColor}">${difficulty}</span>
        </div>
      </div>
    </div>

    ${filterDesc ? `<div class="filter-box"><strong>Active filter:</strong> ${filterDesc}</div>` : ''}

    ${bodyHtml}

    <div class="hints-box">
      <div class="hints-title">&#128273; Hints</div>
      ${hintItems}
    </div>

    <a href="/challenges" class="btn btn-back" style="margin-top:24px">← All Challenges</a>
  </main>

  <div class="toast" id="toast"></div>

  <script>
    // Intercept alert/confirm/prompt — success detection
    const _origAlert = window.alert;
    window.alert = function(msg) {
      document.getElementById('winBanner').style.display = '';
      document.getElementById('winBanner').scrollIntoView({ behavior: 'smooth' });
      const key = 'ch_solved_${num}';
      localStorage.setItem(key, '1');
      _origAlert.call(window, msg);
    };
    window.confirm = function(msg) { window.alert(msg); return true; };
    window.prompt  = function(msg) { window.alert(msg); return ''; };

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.classList.add('show');
      setTimeout(() => t.classList.remove('show'), 2200);
    }
  </script>
</body>
</html>`;
}

// Challenge 1 — Basic Reflected, no filter
app.get('/api/challenges/1', (req, res) => {
  const q = req.query.q || '';
  res.set('Content-Type', 'text/html');
  res.send(buildChallengePage(1, 'Basic Reflected XSS', 'Easy',
    'None — raw input reflected directly.',
    `<div class="ch-form-box">
      <form method="GET" action="/api/challenges/1">
        <label>Search query</label>
        <input type="text" name="q" value="${q}" placeholder="Try a payload here..." autocomplete="off">
        <button type="submit" class="btn btn-vuln">Search</button>
      </form>
    </div>
    ${q ? `<div class="ch-output">Results for: ${q}</div>` : ''}`,
    [
      'XSS requires injecting a script that runs in the browser.',
      'Try the classic: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>',
      'No filter is applied — anything you type is reflected directly into the HTML.'
    ]
  ));
});

// Challenge 2 — Script tag stripped (case-sensitive, single pass)
app.get('/api/challenges/2', (req, res) => {
  const q = (req.query.q || '').replace(/<script>/gi, '').replace(/<\/script>/gi, '');
  res.set('Content-Type', 'text/html');
  res.send(buildChallengePage(2, 'Script Tag Filter', 'Easy',
    '<code>&lt;script&gt;</code> and <code>&lt;/script&gt;</code> are stripped (case-insensitive).',
    `<div class="ch-form-box">
      <form method="GET" action="/api/challenges/2">
        <label>Search query</label>
        <input type="text" name="q" value="${q}" placeholder="script tags are blocked..." autocomplete="off">
        <button type="submit" class="btn btn-vuln">Search</button>
      </form>
    </div>
    ${q ? `<div class="ch-output">Results for: ${q}</div>` : ''}`,
    [
      '<code>&lt;script&gt;</code> is blocked — but there are many other HTML elements that execute JS.',
      'Event handlers like <code>onerror</code>, <code>onload</code>, <code>onfocus</code> work without <code>&lt;script&gt;</code>.',
      'Try: <code>&lt;img src=x onerror=alert(1)&gt;</code>'
    ]
  ));
});

// Challenge 3 — Aggressive filter: strips script tags + on* handlers + javascript:
app.get('/api/challenges/3', (req, res) => {
  let q = req.query.q || '';
  q = q.replace(/<script[\s\S]*?>/gi, '')
       .replace(/<\/script>/gi, '')
       .replace(/\bon\w+\s*=/gi, '')
       .replace(/javascript:/gi, '');
  res.set('Content-Type', 'text/html');
  res.send(buildChallengePage(3, 'Aggressive Filter Bypass', 'Medium',
    '<code>&lt;script&gt;</code> stripped, <code>on*=</code> event handlers stripped, <code>javascript:</code> stripped.',
    `<div class="ch-form-box">
      <form method="GET" action="/api/challenges/3">
        <label>Search query</label>
        <input type="text" name="q" value="${q}" placeholder="script and events blocked..." autocomplete="off">
        <button type="submit" class="btn btn-vuln">Search</button>
      </form>
    </div>
    ${q ? `<div class="ch-output">Results for: ${q}</div>` : ''}`,
    [
      'The filter is regex-based and strips known keywords — but can it handle all cases?',
      'Try stacking: <code>&lt;img src=x oNerror=alert(1)&gt;</code> — the filter is case-insensitive now... but what about <code>data:</code> URIs?',
      'Try: <code>&lt;svg&gt;&lt;animate onbegin=alert(1)&gt;&lt;/svg&gt;</code> — <code>onbegin</code> is a valid SVG event.',
      'Or: <code>&lt;iframe srcdoc="&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;"&gt;</code>'
    ]
  ));
});

// Challenge 4 — Unquoted attribute context
app.get('/api/challenges/4', (req, res) => {
  const color = req.query.color || 'lightblue';
  res.set('Content-Type', 'text/html');
  res.send(buildChallengePage(4, 'Attribute Context Injection', 'Medium',
    'Input is placed inside an <strong>unquoted</strong> HTML attribute.',
    `<div class="ch-form-box">
      <form method="GET" action="/api/challenges/4">
        <label>Pick a background color</label>
        <input type="text" name="color" value="${color}" placeholder='Try: red" onmouseover="alert(1)' autocomplete="off">
        <button type="submit" class="btn btn-vuln">Apply Color</button>
      </form>
    </div>
    <div class="ch-output" style="background:${color};padding:24px;text-align:center;border-radius:8px;margin-top:12px">
      Preview area — hover me after submitting
    </div>
    <div class="ch-source">Server renders: <code>&lt;div style="background:${escapeHtml(color)}"&gt;</code></div>`,
    [
      'The value lands inside a <code>style</code> attribute with no quoting: <code>style="background:COLOR"</code>.',
      'A <code>"</code> in your input closes the attribute — anything after becomes new HTML.',
      'Try: <code>red" onmouseover="alert(1)</code> — hover the preview after submitting.'
    ]
  ));
});

// Challenge 5 — JS string context
app.get('/api/challenges/5', (req, res) => {
  const name = req.query.name || 'visitor';
  res.set('Content-Type', 'text/html');
  res.send(buildChallengePage(5, 'JS String Context Injection', 'Medium',
    'Input is embedded inside a <code>&lt;script&gt;</code> block string literal.',
    `<div class="ch-form-box">
      <form method="GET" action="/api/challenges/5">
        <label>Your name</label>
        <input type="text" name="name" value="${name}" placeholder='Try: "; alert(1);//' autocomplete="off">
        <button type="submit" class="btn btn-vuln">Greet Me</button>
      </form>
    </div>
    <div class="ch-output" id="greeting">Loading...</div>
    <div class="ch-source">Server renders: <code>var userName = "${escapeHtml(name)}";</code></div>
    <script>
      var userName = "${name}";
      document.getElementById('greeting').textContent = 'Hello, ' + userName + '!';
    </script>`,
    [
      'The value is placed inside a JS string: <code>var userName = "YOUR_INPUT";</code>',
      'A <code>"</code> closes the string — code after it executes.',
      'Try: <code>"; alert(1);//</code> — the <code>//</code> comments out the trailing quote.'
    ]
  ));
});

// Challenge 6 — User-Agent header reflection
app.get('/api/challenges/6', (req, res) => {
  const ua = req.headers['user-agent'] || '';
  res.set('Content-Type', 'text/html');
  res.send(buildChallengePage(6, 'HTTP Header Injection (User-Agent)', 'Hard',
    'Your <code>User-Agent</code> header is reflected raw into the page — forms won\'t help here.',
    `<div class="ch-form-box" style="background:#fef2f2;border-color:#fca5a5">
      <p style="font-size:.875rem;color:#7f1d1d;margin-bottom:10px">
        <strong>This challenge requires a tool that can set custom HTTP headers.</strong><br>
        Use <code>curl</code>, Burp Suite, or browser DevTools to send a crafted <code>User-Agent</code>.
      </p>
      <div class="code-block" style="margin:0">curl "http://localhost:3001/api/challenges/6" \\
  -H 'User-Agent: &lt;script&gt;alert(1)&lt;/script&gt;'</div>
    </div>
    <div class="ch-output">
      <strong>Your User-Agent:</strong><br>
      <span style="font-family:monospace;font-size:.85rem;word-break:break-all">${ua}</span>
    </div>
    <div class="ch-source">Server renders: <code>&lt;span&gt;${escapeHtml(ua)}&lt;/span&gt;</code> — but the actual page does not escape it.</div>`,
    [
      'Forms only control URL parameters and POST bodies — not HTTP headers.',
      'Use <code>curl -H "User-Agent: PAYLOAD" http://localhost:3001/api/challenges/6</code>',
      'Or use Burp Suite Repeater: intercept the request and edit the User-Agent header.',
      'Classic payload: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> as the User-Agent value.'
    ]
  ));
});

// Challenge 7 — Stored XSS (comment board)
const ch7Comments = [];

app.get('/api/challenges/7', (req, res) => {
  const board = ch7Comments.map(c =>
    `<div class="comment-card">
      <div class="comment-author">${c.author}</div>
      <div class="comment-body">${c.body}</div>
      <div class="comment-time">${c.time}</div>
    </div>`
  ).join('') || '<p class="empty">No posts yet — be the first.</p>';

  res.set('Content-Type', 'text/html');
  res.send(buildChallengePage(7, 'Stored XSS — Comment Board', 'Hard',
    'No sanitization on storage or render. Payload persists and fires for every visitor.',
    `<div class="ch-form-box">
      <form method="POST" action="/api/challenges/7">
        <label>Name</label>
        <input type="text" name="author" placeholder="Your name" required>
        <label style="margin-top:8px">Comment</label>
        <textarea name="body" rows="3" placeholder="Post a payload — it executes for all visitors" required></textarea>
        <button type="submit" class="btn btn-vuln" style="margin-top:8px">Post</button>
      </form>
    </div>
    <div class="comments-section" style="margin-top:20px">
      <h3 style="font-size:.95rem;font-weight:700;margin-bottom:12px;color:var(--gray-600)">
        Posts (${ch7Comments.length})
      </h3>
      ${board}
    </div>`,
    [
      'Stored XSS: the payload is saved to the server and executed every time the page loads.',
      'Post an XSS payload as your comment body — refresh and watch it fire.',
      'Try: <code>&lt;img src=x onerror=alert(document.cookie)&gt;</code> as the comment.'
    ]
  ));
});

app.post('/api/challenges/7', (req, res) => {
  const { author, body } = req.body;
  ch7Comments.push({ author: author || 'Anonymous', body: body || '', time: new Date().toLocaleString() });
  res.redirect('/api/challenges/7');
});

// Challenge 8 — href javascript: injection
app.get('/api/challenges/8', (req, res) => {
  const url = req.query.url || 'https://example.com';
  res.set('Content-Type', 'text/html');
  res.send(buildChallengePage(8, 'href javascript: Injection', 'Hard',
    '<code>escapeHtml()</code> is applied — but it\'s the wrong defense for URL context.',
    `<div class="ch-form-box">
      <form method="GET" action="/api/challenges/8">
        <label>Enter a website URL</label>
        <input type="text" name="url" value="${escapeHtml(url)}" placeholder="javascript:alert(1)" autocomplete="off">
        <button type="submit" class="btn btn-vuln">Save Link</button>
      </form>
    </div>
    <div class="ch-output">
      <strong>Your link:</strong>
      <a href="${escapeHtml(url)}" style="color:#2563eb;margin-left:8px">Click me</a>
      <br><small style="color:#9ca3af">href="${escapeHtml(url)}"</small>
    </div>
    <div class="ch-source">The developer used <code>escapeHtml()</code> thinking it was safe. Click the link to trigger.</div>`,
    [
      '<code>escapeHtml()</code> encodes <code>&lt; &gt; " &apos; &amp;</code> — but <code>javascript:alert(1)</code> contains none of those characters.',
      '<code>escapeHtml("javascript:alert(1)")</code> returns <code>"javascript:alert(1)"</code> — identical, unchanged.',
      'Submit <code>javascript:alert(1)</code> as the URL, then click the link.',
      'Fix requires a URL scheme allowlist, not HTML escaping.'
    ]
  ));
});

// Secure Challenge — all defenses, truly not bypassable
app.get('/api/challenges/secure', (req, res) => {
  const q    = escapeHtml(req.query.q    || '');
  const color = escapeHtml(req.query.color || 'lightblue');
  const url   = escapeHtml(safeUrl(req.query.url || 'https://example.com'));
  const name  = safeJsonForScript(req.query.name || 'visitor');

  res.set('Content-Type', 'text/html');
  res.set('Content-Security-Policy', SECURE_CSP);
  res.send(buildChallengePage('S', 'The Secure Form — Try to Break It', 'Expert',
    'All defenses active: <code>escapeHtml()</code>, <code>safeUrl()</code>, <code>safeJsonForScript()</code>, CSP header.',
    `<div class="note secure" style="margin-bottom:16px">
      <span>&#10003;</span>
      <div>Every input is correctly encoded for its context. Try all payloads — none should execute.</div>
    </div>
    <div class="ch-form-box">
      <form method="GET" action="/api/challenges/secure">
        <label>Search (HTML body context)</label>
        <input type="text" name="q" value="${q}" autocomplete="off">
        <label style="margin-top:8px">Color (attribute context)</label>
        <input type="text" name="color" value="${color}" autocomplete="off">
        <label style="margin-top:8px">URL (href context)</label>
        <input type="text" name="url" value="${url}" autocomplete="off">
        <label style="margin-top:8px">Name (JS string context)</label>
        <input type="text" name="name" autocomplete="off">
        <button type="submit" class="btn btn-secure" style="margin-top:8px">Submit</button>
      </form>
    </div>
    ${q ? `<div class="ch-output">Search: ${q}</div>` : ''}
    <div class="ch-output" style="background:${color};padding:16px;border-radius:8px;margin-top:12px;text-align:center">
      Color preview
    </div>
    <div class="ch-output" style="margin-top:12px">
      Link: <a href="${url}" style="color:#2563eb">${url}</a>
    </div>
    <script>
      var userName = ${name};
      document.querySelector('.ch-output')?.setAttribute('data-user', userName);
    </script>`,
    [
      'This form is genuinely secure. All payloads are neutralized.',
      'HTML body uses <code>escapeHtml()</code> — tags become literal text.',
      'Attribute uses quoted + <code>escapeHtml()</code> — <code>"</code> becomes <code>&amp;quot;</code>.',
      'href uses <code>safeUrl()</code> allowlist — <code>javascript:</code> → <code>#blocked</code>.',
      'JS string uses <code>safeJsonForScript()</code> — string cannot break out.'
    ]
  ));
});

app.listen(PORT, () => {
  console.log(`XSS Demo running at http://localhost:${PORT}`);
});
