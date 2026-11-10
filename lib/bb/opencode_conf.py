"""Read OpenCode configuration to discover providers, models, and API settings.

Used to "grab models and apis" from the user's OpenCode install so `bb` can
offer them without duplicating credentials in this repo.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from lib.bb import config

_JSONC_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


def _candidate_config_paths() -> list[Path]:
    paths: list[Path] = []
    env = os.environ.get("OPENCODE_CONFIG")
    if env:
        paths.append(Path(env).expanduser())
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    for name in ("opencode.json", "opencode.jsonc", "config.json"):
        paths.append(base / "opencode" / name)
    # de-dupe preserving order
    seen = set()
    out = []
    for p in paths:
        rp = str(p)
        if rp in seen:
            continue
        seen.add(rp)
        out.append(p)
    return out


def _strip_jsonc(text: str) -> str:
    # remove // and /* */ comments, then trailing commas (best-effort)
    out = []
    i = 0
    n = len(text)
    in_str = False
    esc = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and nxt == "/":
            i += 2
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if c == "/" and nxt == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    cleaned = "".join(out)
    # strip trailing commas repeatedly
    prev = None
    while cleaned != prev:
        prev = cleaned
        cleaned = _JSONC_TRAILING_COMMA_RE.sub(r"\1", cleaned)
    return cleaned


def load_opencode_config(path: str | Path | None = None) -> tuple[dict, Path | None]:
    """Return (config_dict, path_used). First readable/parseable wins."""
    candidates = [Path(path).expanduser()] if path else _candidate_config_paths()
    for p in candidates:
        try:
            raw = p.read_text(encoding="utf-8")
        except OSError:
            continue
        if not raw.strip():
            continue
        try:
            data = json.loads(raw)
        except ValueError:
            try:
                data = json.loads(_strip_jsonc(raw))
            except ValueError:
                continue
        if isinstance(data, dict):
            return data, p
    return {}, None


def _auth_paths() -> list[Path]:
    paths = []
    xdg_data = os.environ.get("XDG_DATA_HOME")
    data_base = Path(xdg_data).expanduser() if xdg_data else Path.home() / ".local" / "share"
    xdg_cfg = os.environ.get("XDG_CONFIG_HOME")
    cfg_base = Path(xdg_cfg).expanduser() if xdg_cfg else Path.home() / ".config"
    paths.append(data_base / "opencode" / "auth.json")
    paths.append(cfg_base / "opencode" / "auth.json")
    return paths


def load_auth() -> dict:
    for p in _auth_paths():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            continue
    return {}


def extract_providers(cfg: dict | None = None) -> dict:
    """provider_id -> {name, baseURL, apiKey, npm, models:{model_id:meta}}."""
    if cfg is None:
        cfg, _ = load_opencode_config()
    providers = cfg.get("provider") or cfg.get("providers") or {}
    if not isinstance(providers, dict):
        return {}
    auth = load_auth()
    out = {}
    for pid, pdata in providers.items():
        if not isinstance(pdata, dict):
            continue
        options = pdata.get("options") or {}
        if not isinstance(options, dict):
            options = {}
        base_url = options.get("baseURL") or options.get("baseUrl") or pdata.get("baseURL")
        api_key = options.get("apiKey") or pdata.get("apiKey")
        # supplement from auth store if missing
        if not api_key and isinstance(auth.get(pid), dict):
            a = auth[pid]
            api_key = a.get("key") or a.get("apiKey") or a.get("token")
        models = pdata.get("models") or {}
        if not isinstance(models, dict):
            models = {}
        norm_models = {}
        for mid, mdata in models.items():
            if isinstance(mdata, dict):
                norm_models[mid] = mdata
            else:
                norm_models[mid] = {"name": str(mdata)}
        out[pid] = {
            "id": pid,
            "name": pdata.get("name") or pid,
            "npm": pdata.get("npm"),
            "baseURL": base_url,
            "apiKey": api_key,
            "models": norm_models,
            "enabled": pdata.get("enabled", True),
        }
    return out


def list_models(cfg: dict | None = None, include_disabled: bool = False) -> list[dict]:
    """Flat list of {ref, provider, provider_name, model_id, name, baseURL, has_api_key, meta}."""
    providers = extract_providers(cfg)
    rows = []
    for pid, prov in sorted(providers.items()):
        if not include_disabled and prov.get("enabled") is False:
            continue
        for mid, meta in sorted((prov.get("models") or {}).items()):
            ref = f"{pid}/{mid}" if "/" not in mid or not mid.startswith(pid + "/") else mid
            # opencode model refs in this workspace commonly appear as provider/model...
            if not ref.startswith(pid + "/"):
                ref = f"{pid}/{mid}"
            rows.append({
                "ref": ref,
                "provider": pid,
                "provider_name": prov.get("name") or pid,
                "model_id": mid,
                "name": (meta or {}).get("name") or mid,
                "baseURL": prov.get("baseURL"),
                "has_api_key": bool(prov.get("apiKey")),
                "meta": meta or {},
            })
    return rows


def default_model(cfg: dict | None = None) -> str | None:
    if cfg is None:
        cfg, _ = load_opencode_config()
    m = cfg.get("model") or cfg.get("defaultModel")
    return m if isinstance(m, str) and m else None


def summarize(cfg: dict | None = None) -> dict:
    if cfg is None:
        cfg, path = load_opencode_config()
    else:
        path = None
    providers = extract_providers(cfg)
    models = list_models(cfg)
    return {
        "config_path": str(path) if path else None,
        "providers": len(providers),
        "models": len(models),
        "default_model": default_model(cfg),
    }
