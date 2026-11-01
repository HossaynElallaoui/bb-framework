"""One long-lived `opencode serve` per `bb run`, plus a tiny HTTP client.

The old driver spawned a fresh `opencode run` process for every agent turn.
That paid process startup, skill loading, and provider handshake 15x per
round. This module keeps a single server alive for the whole run and routes
each specialist turn through an HTTP session instead.

Only stdlib is used: the server is local, the payloads are small, and a
dependency-free client is easier to reason about than a vendored SDK.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_PERMISSIONS = {
    "bash": "allow",
    "edit": "allow",
    "read": "allow",
    "glob": "allow",
    "grep": "allow",
    "list": "allow",
    "external_directory": "allow",
    "webfetch": "allow",
    "websearch": "allow",
    "task": "allow",
}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _merge_permission_env(env: dict[str, str]) -> None:
    raw = env.get("OPENCODE_CONFIG_CONTENT", "").strip()
    cfg = {}
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                cfg = parsed
        except ValueError:
            pass
    perm = cfg.get("permission")
    if not isinstance(perm, dict):
        perm = {}
    for key, value in DEFAULT_PERMISSIONS.items():
        perm.setdefault(key, value)
    cfg["permission"] = perm
    env["OPENCODE_CONFIG_CONTENT"] = json.dumps(cfg)


@dataclass
class PromptResult:
    ok: bool
    text: str = ""
    tokens: dict = field(default_factory=dict)
    cost: float = 0.0
    session: str = ""
    error: str = ""
    raw: dict = field(default_factory=dict)


class OpenCodeServer:
    """Owns one `opencode serve` child process."""

    def __init__(self, base: Path, log_dir: Path | None = None,
                 port: int | None = None, startup_timeout: float = 30.0,
                 model: str | None = None, extra_env: dict | None = None):
        self.base = Path(base)
        self.log_dir = Path(log_dir) if log_dir else self.base / "agent_logs"
        self.port = port or _free_port()
        self.startup_timeout = startup_timeout
        self.model = model
        self.extra_env = extra_env or {}
        self.proc: subprocess.Popen | None = None
        self._log_fh = None
        self._stream_stop = None
        self._stream_thread = None
        self.url = f"http://127.0.0.1:{self.port}"

    # ---- lifecycle ----

    def start(self) -> "OpenCodeServer":
        if self.proc and self.proc.poll() is None:
            return self
        self.log_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.log_dir / "opencode-server.log"
        self._log_fh = open(log_path, "a")
        env = os.environ.copy()
        env.update({k: str(v) for k, v in self.extra_env.items()})
        _merge_permission_env(env)
        self.proc = subprocess.Popen(
            ["opencode", "serve", "--port", str(self.port),
             "--hostname", "127.0.0.1"],
            cwd=str(self.base), env=env,
            stdout=self._log_fh, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.time() + self.startup_timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"opencode serve exited with {self.proc.returncode}; "
                    f"see {log_path}")
            try:
                health = self._request("GET", "/global/health", timeout=2)
                if health.get("healthy"):
                    return self
            except (urllib.error.URLError, OSError, ValueError):
                pass
            time.sleep(0.25)
        self.stop()
        raise RuntimeError(f"opencode serve did not become healthy; see {log_path}")

    def start_event_stream(self, callback) -> None:
        """Consume /event on a daemon thread; callback gets decoded events."""
        import threading
        if self._stream_thread and self._stream_thread.is_alive():
            return
        stop_event = threading.Event()
        self._stream_stop = stop_event

        def _loop():
            while not stop_event.is_set():
                try:
                    for event in self.stream_events(timeout=2):
                        if stop_event.is_set():
                            return
                        try:
                            callback(event)
                        except Exception:
                            pass
                except Exception:
                    if not stop_event.is_set():
                        time.sleep(0.5)

        self._stream_thread = threading.Thread(target=_loop, daemon=True,
                                               name="opencode-events")
        self._stream_thread.start()

    def stop(self) -> None:
        if self._stream_stop is not None:
            self._stream_stop.set()
        # Do not null the event here: the daemon loop still reads it. Join
        # briefly so teardown cannot race the check.
        if self._stream_thread is not None:
            self._stream_thread.join(timeout=2)
        self._stream_stop = None
        self._stream_thread = None
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        self.proc = None
        if self._log_fh:
            try:
                self._log_fh.close()
            except OSError:
                pass
            self._log_fh = None

    def __enter__(self) -> "OpenCodeServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ---- HTTP ----

    def _request(self, method: str, path: str, body: dict | None = None,
                 query: dict | None = None, timeout: float = 30) -> dict:
        url = self.url + path
        if query:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in query.items() if v is not None})
        data = json.dumps(body).encode() if body is not None else None
        headers = {"content-type": "application/json"} if data else {}
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
        if not raw:
            return {}
        return json.loads(raw)

    def create_session(self, directory: Path | None = None,
                       title: str = "bb") -> str:
        directory = Path(directory or self.base)
        data = self._request("POST", "/session",
                             body={"title": title},
                             query={"directory": str(directory)})
        sid = data.get("id")
        if not isinstance(sid, str) or not sid.startswith("ses_"):
            raise RuntimeError(f"session.create returned no session id: {data!r}")
        return sid

    def messages(self, session_id: str, directory: Path | None = None,
                 limit: int = 100) -> list[dict]:
        directory = Path(directory or self.base)
        data = self._request(
            "GET", f"/session/{session_id}/message",
            query={"directory": str(directory), "limit": limit},
            timeout=30)
        return data if isinstance(data, list) else []

    def prompt(self, session_id: str, text: str,
               directory: Path | None = None, agent: str | None = None,
               system: str | None = None, model: str | None = None,
               timeout: float = 900) -> PromptResult:
        directory = Path(directory or self.base)
        body: dict = {"parts": [{"type": "text", "text": text}]}
        if agent:
            body["agent"] = agent
        if system:
            body["system"] = system
        model = model or self.model
        if model and "/" in model:
            provider, model_id = model.split("/", 1)
            body["model"] = {"providerID": provider, "modelID": model_id}
        started_ms = int(time.time() * 1000)
        try:
            resp = self._request(
                "POST", f"/session/{session_id}/message",
                body=body,
                query={"directory": str(directory)},
                timeout=timeout,
            )
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode(errors="replace")[:500]
            except OSError:
                pass
            return PromptResult(False, session=session_id,
                                error=f"HTTP {exc.code}: {detail}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # Client timeout does not mean the server did nothing. Pull the
            # partial turn so tokens/tool output are not silently lost.
            partial = self._collect_turn(session_id, {}, directory, started_ms)
            partial.ok = False
            partial.error = str(exc)
            return partial
        return self._collect_turn(session_id, resp, directory, started_ms)

    def _collect_turn(self, session_id: str, resp: dict, directory: Path,
                      started_ms: int) -> PromptResult:
        """The prompt response only carries the last assistant message.
        Fetch the session tail to account for tool-call steps and tokens."""
        messages: list[dict] = []
        try:
            messages = self.messages(session_id, directory, limit=100)
        except (urllib.error.URLError, OSError, ValueError):
            pass
        fresh = []
        for m in messages:
            info = m.get("info") or {}
            created = (info.get("time") or {}).get("created", 0)
            if info.get("role") == "assistant" and created >= started_ms - 1000:
                fresh.append(m)
        if not fresh and isinstance(resp, dict) and resp.get("info"):
            fresh = [resp]

        tokens = {"total": 0, "input": 0, "output": 0, "reasoning": 0,
                  "cache": {"read": 0, "write": 0}}
        cost = 0.0
        texts: list[str] = []
        tool_tails: list[str] = []
        errors: list[str] = []
        for m in fresh:
            info = m.get("info") or {}
            t = info.get("tokens") or {}
            for key in ("total", "input", "output", "reasoning"):
                tokens[key] = tokens.get(key, 0) + int(t.get(key) or 0)
            cache = t.get("cache") or {}
            for key in ("read", "write"):
                tokens["cache"][key] += int(cache.get(key) or 0)
            cost += float(info.get("cost") or 0)
            if info.get("error"):
                errors.append(str(info["error"])[:300])
            for part in m.get("parts") or []:
                ptype = part.get("type")
                if ptype == "text" and part.get("text"):
                    texts.append(part["text"])
                elif ptype == "tool":
                    state = part.get("state") or {}
                    out = state.get("output") or ""
                    if out:
                        tool_tails.append(str(out)[-1200:])
        text = "\n".join(texts).strip()
        if not text and tool_tails:
            text = tool_tails[-1]
        return PromptResult(not errors and bool(fresh), text=text,
                            tokens=tokens, cost=cost, session=session_id,
                            error="; ".join(errors), raw=resp)

    def stream_events(self, timeout: float = 1.0):
        """Yield decoded SSE events. Used by the live UI; caller closes."""
        req = urllib.request.Request(self.url + "/event", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw in resp:
                line = raw.decode(errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if not payload:
                    continue
                try:
                    yield json.loads(payload)
                except ValueError:
                    continue
