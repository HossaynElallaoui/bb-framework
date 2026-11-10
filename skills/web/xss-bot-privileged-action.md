# Skill: Stored XSS against an admin bot → privileged action via in-page fetch

Trigger: stored input renders in wp-admin (list/table/meta box) with a bot/headless
browser reviewing it periodically (HTB-style XSS boxes).

Procedure:
1. Beacon first: minimal payload that reports `location.href`, `document.cookie`,
   UA. Confirms fire + execution origin in ≤2 bot cycles.
2. If auth cookies are HttpOnly (only `wp-settings-*` visible), don't exfil cookies —
   perform the privileged action **as the victim**:
   - `fetch('/wp-admin/<page>')` → parse with `DOMParser` + `querySelector`
     (NEVER put literal `"` inside `onerror="…"`; it truncates the attribute —
     use selectors or `\x22`).
   - scrape the action's per-session `_wpnonce` (+ `_wp_http_referer` if present).
   - POST the action with the victim's cookies (create admin, edit theme, etc.).
   - beacon result status back to your listener.
3. Verify the privileged effect by logging in / requesting the artifact yourself.

Pitfalls:
- WP alternates `'` vs `"` in HTML per request — make regexes quote-agnostic or
  parse the DOM.
- If a create/edit "succeeds" but nothing changes, check whether the endpoint
  refused silently (re-fetch target page and confirm nonce value differs).
- Cold-start race: first admin request after login may not render the editor —
  warm up with `/wp-admin/` first and retry the editor page.
