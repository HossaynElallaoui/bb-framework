# Flask session + JWT offline key crack

Trigger: a Flask app returns a signed `session` cookie and/or an HS256 JWT,
and you want to test weak/default signing keys without hammering the app.

## Procedure

1. Capture one Flask session cookie and one live HS256 JWT from the app.
   Keep them in the workspace; do not write to `/tmp` (the harness
   auto-rejects external directories).
2. Crack the JWT with hashcat mode 16500. Drop truncated log lines first:
   a valid JWT has three dot-separated parts and a signature of 40+ chars.
   ```
   hashcat -m 16500 jwt_hashes.txt rockyou.txt --force
   hashcat -m 16500 jwt_hashes.txt --show
   ```
3. If `flask-unsign` is absent, verify Flask cookies directly. Flask's
   `SecureCookieSessionInterface` uses itsdangerous `URLSafeTimedSerializer`
   with `salt='cookie-session'`, `key_derivation='hmac'`, `digest_method=sha1`
   and compression. The cookie is `payload.timestamp.signature`, where the
   signing input is `value.rsplit('.', 1)[0]` (keep any leading dot).
   Derived key and signature:
   ```
   key = HMAC-SHA1(secret, b"cookie-session")
   sig = HMAC-SHA1(key, signing_input)
   ```
   Compare the raw digest to the base64url-decoded signature. This avoids
   constructing a Flask app per candidate and is fast enough for rockyou.
4. Sanity-check the formula offline: create a Flask app with a known
   `secret_key`, dump a session, and confirm your manual check matches the
   generated signature before running the wordlist.
5. Test any recovered secret on both the JWT and the Flask cookie; apps often
   reuse one `SECRET_KEY`.

## Pitfalls

- A negative wordlist run does not refute forgery: the remaining tests are
  `alg=none`, stripped/re-encoded signatures, and claim tampering.
- Log lines from agent transcripts may truncate tokens; filter to three
  parts with a full-length signature or hashcat reports "Token length
  exception".
- Flask cookies begin with a dot and split into four parts (`''`, payload,
  timestamp, signature). Include the leading dot in the signing input.
- Use rockyou (14.3M) only after a small app-themed list; report the negative
  result so teammates do not repeat it.
