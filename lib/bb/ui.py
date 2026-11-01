"""Terminal presentation. Rich when available; plain text otherwise.

Live rendering is intentionally self-contained: the runner builds a status
dict, this module renders it. Nothing here reads state or calls a model.
"""

from __future__ import annotations

import json
import sys
import threading
from collections import deque
from datetime import datetime, timezone

try:  # rich is installed on the target box; keep a graceful fallback anyway
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TextColumn
    from rich.spinner import Spinner
    from rich.table import Table
    from rich.text import Text
    HAVE_RICH = True
except Exception:  # pragma: no cover - fallback path
    Console = Live = Panel = Progress = Table = Text = None
    Spinner = None
    HAVE_RICH = False

ROLE_COLORS = {
    "orchestrator": "bright_white",
    "critic-agent": "bright_red",
    "recon-agent": "cyan",
    "web-agent": "magenta",
    "ad-agent": "blue",
    "privesc-agent": "yellow",
    "linux-privesc-agent": "green",
    "user": "bright_cyan",
    "bb": "bright_white",
}

console = Console(highlight=False) if HAVE_RICH else None


def enabled(no_ui: bool = False) -> bool:
    if no_ui or not HAVE_RICH:
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _color(role: str) -> str:
    return ROLE_COLORS.get(role, "white")


def log(role: str, message: str, level: str = "info") -> None:
    """One colored log line, safe in both rich and plain modes."""
    prefix = f"[{role}]"
    if HAVE_RICH:
        style = _color(role)
        if level == "error":
            style = "bold red"
        elif level == "warn":
            style = "yellow"
        console.print(f"[{style}]{prefix}[/] {message}", markup=True, soft_wrap=True)
    else:
        print(f"{prefix} {message}", file=sys.stderr if level == "error" else sys.stdout)


def table(title: str, columns: list[str], rows: list[list], **kwargs) -> None:
    if not HAVE_RICH:
        print(f"\n== {title} ==")
        print(" | ".join(columns))
        for row in rows:
            print(" | ".join(str(c) for c in row))
        return
    t = Table(title=title, header_style="bold", title_style="bold bright_white",
              show_lines=False, **kwargs)
    for c in columns:
        t.add_column(str(c), overflow="fold")
    for row in rows:
        t.add_row(*[Text(str(c)) if not isinstance(c, Text) else c for c in row])
    console.print(t)


def panel(title: str, body: str, style: str = "bright_blue") -> None:
    if not HAVE_RICH:
        print(f"\n=== {title} ===\n{body}")
        return
    console.print(Panel(body, title=title, border_style=style))


def kv_table(title: str, data: dict) -> None:
    table(title, ["key", "value"], [[k, v] for k, v in data.items()])


def json_out(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


class LiveStatus:
    """Live round/agent/hypothesis panel for `bb run`.

    `update(**fields)` merges into the status dict and re-renders; `log()` keeps
    a short ring buffer visible in the panel while also writing a plain line so
    scrollback is still useful after the run.
    """

    def __init__(self, no_ui: bool = False, max_logs: int = 7):
        self.active = enabled(no_ui)
        self.status: dict = {}
        self.logs: deque[str] = deque(maxlen=max_logs)
        self._live = None
        self._lock = threading.Lock()
        self._started = datetime.now(timezone.utc)

    def start(self) -> "LiveStatus":
        if self.active and HAVE_RICH:
            self._live = Live(self._render(), console=console, refresh_per_second=6,
                              transient=False)
            self._live.start()
        return self

    def stop(self) -> None:
        if self._live is not None:
            try:
                self._live.update(self._render())
                self._live.stop()
            except Exception:
                pass
            self._live = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False

    def update(self, **fields) -> None:
        with self._lock:
            self.status.update(fields)
            if self._live is not None:
                try:
                    self._live.update(self._render(), refresh=True)
                except Exception:
                    pass

    def log(self, role: str, message: str, level: str = "info") -> None:
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.logs.append(f"{stamp} [{role}] {message}")
        if self.active and HAVE_RICH:
            try:
                console.print(f"[{_color(role)}]\\[{stamp}] {role}[/] {message}")
            except Exception:
                pass
        else:
            print(f"[{stamp}] [{role}] {message}")

    def _render(self):
        if not HAVE_RICH:
            return ""
        st = self.status
        elapsed = int(st.get("elapsed", 0))
        mm, ss = divmod(elapsed, 60)
        hh, mm = divmod(mm, 60)
        state = st.get("state", "starting")
        body = Text()
        body.append(f"round {st.get('round', 0)}/{st.get('max_rounds', '?')}", style="bold")
        body.append(f"   {state}   ")
        body.append(f"{hh:02d}:{mm:02d}:{ss:02d}", style="dim")
        body.append(f"   actions={st.get('actions', 0)}  dead_ends={st.get('dead_ends', 0)}")
        body.append(f"   hyp={st.get('hypothesis', '-')}")
        body.append("\n")
        body.append(f"agent: {st.get('agent', '-')}   workspace: {st.get('workspace', '-')}",
                    style="dim")
        lim = st.get("limiter") or {}
        if lim:
            body.append(f"\nparallel: {lim.get('active', 0)}/{lim.get('parallel', '?')}"
                        f" (max {lim.get('max_parallel', '?')})", style="cyan")
            if lim.get("cooldown"):
                body.append(f"   cooldown {lim['cooldown']:.0f}s", style="yellow")
            if lim.get("rate_per_min"):
                body.append(f"   cap {lim['rate_per_min']:.0f}/min", style="dim")
        tok = (st.get("tokens") or {}).get("total") or {}
        if tok:
            total = int(tok.get("total") or 0)
            body.append(f"   tokens={total:,} in={int(tok.get('input') or 0):,} "
                        f"out={int(tok.get('output') or 0):,}", style="dim")
        if st.get("milestones"):
            body.append(f"\nmilestones: {', '.join(st['milestones'])}", style="green")
        if st.get("warning"):
            body.append(f"\n⚠ {st['warning']}", style="yellow")
        if st.get("stream_text"):
            stream = " ".join(str(st["stream_text"]).split())
            body.append(f"\n{st.get('stream_agent', '-')}: {stream[-300:]}",
                        style="dim")
        prog = st.get("progress")
        if prog is not None:
            width = 28
            filled = int(width * max(0.0, min(1.0, prog)))
            body.append("\n")
            body.append("[" + "█" * filled + "░" * (width - filled) + "]", style="cyan")
            body.append(f" {int(prog * 100)}%")
        if self.logs:
            body.append("\n")
            for line in self.logs:
                body.append(line + "\n", style="dim")
        return Panel(body, title="bb run", border_style="bright_blue")


def boxed_summary(title: str, summary: dict, note: str | None = None) -> None:
    if HAVE_RICH:
        lines = []
        for k, v in summary.items():
            lines.append(f"[bold]{k}:[/] {v}")
        if note:
            lines.append("")
            lines.append(note)
        console.print(Panel("\n".join(lines), title=title, border_style="green"))
    else:
        print(f"\n=== {title} ===")
        for k, v in summary.items():
            print(f"{k}: {v}")
        if note:
            print(note)


def spinner_text(text: str) -> str:
    return text
