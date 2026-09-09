"""Configuration (build plan §36).

JSON config (stdlib-only project; documented format):
{
  "limits": {"max_message_bytes": 65536, ...},
  "listeners": [
    {"type": "udp", "host": "0.0.0.0", "port": 5514},
    {"type": "tcp", "host": "0.0.0.0", "port": 5601},
    {"type": "file", "path": "C:/logs/app.log", "follow": true}
  ],
  "sources": [
    {"source_id": "firewall-a", "transport": "udp", "peer_ip": "10.0.0.1",
     "vendor": "Fortinet", "product": "FortiGate", "parser_hint": "fortigate"}
  ],
  "siem": {
    "type": "spool|syslog|qradar|elastic",
    "path": "...",                # spool
    "host": "...", "port": 514, "transport": "udp|tcp",  # syslog/qradar
    "url": "https://...", "index_prefix": "ulstp", "api_key_env": "ES_API_KEY",
    "batch_size": 100
  },
  "api": {"host": "127.0.0.1", "port": 8080}
}

Credentials come from environment variables referenced by *_env keys —
never inline in config, never logged (Skill 08).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .errors import ConfigError
from .limits import ResourceLimits
from .source_id import SourceDefinition


def load_config(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    except ValueError as exc:
        raise ConfigError(f"invalid JSON in {path}: {exc}") from exc
    validate_config(cfg)
    return cfg


def validate_config(cfg: Dict[str, Any]) -> None:
    if not isinstance(cfg, dict):
        raise ConfigError("config root must be an object")
    for listener in cfg.get("listeners", []):
        t = listener.get("type")
        if t not in ("udp", "tcp", "file"):
            raise ConfigError(f"listener type must be udp|tcp|file, got {t!r}")
        if t == "file" and not listener.get("path"):
            raise ConfigError("file listener requires 'path'")
        if t in ("udp", "tcp") and not listener.get("port"):
            raise ConfigError(f"{t} listener requires 'port'")
    siem = cfg.get("siem")
    if siem is not None:
        stype = siem.get("type")
        if stype not in ("spool", "syslog", "qradar", "elastic"):
            raise ConfigError(f"siem.type must be spool|syslog|qradar|elastic, got {stype!r}")
        if stype == "spool" and not siem.get("path"):
            raise ConfigError("siem.type=spool requires 'path'")
        if stype in ("syslog", "qradar") and not (siem.get("host") and siem.get("port")):
            raise ConfigError(f"siem.type={stype} requires 'host' and 'port'")
        if stype == "elastic" and not siem.get("url"):
            raise ConfigError("siem.type=elastic requires 'url'")


def build_limits(cfg: Dict[str, Any]) -> ResourceLimits:
    overrides = cfg.get("limits", {})
    allowed = {f for f in ResourceLimits.__dataclass_fields__}
    bad = set(overrides) - allowed
    if bad:
        raise ConfigError(f"unknown limit keys: {sorted(bad)}")
    return ResourceLimits(**overrides)


def build_source_definitions(cfg: Dict[str, Any]) -> List[SourceDefinition]:
    defs: List[SourceDefinition] = []
    for s in cfg.get("sources", []):
        if not s.get("source_id"):
            raise ConfigError("source definition requires 'source_id'")
        defs.append(SourceDefinition(
            source_id=s["source_id"],
            vendor=s.get("vendor"),
            product=s.get("product"),
            transport=s.get("transport"),
            peer_ip=s.get("peer_ip"),
            local_port=s.get("port"),
            file_path=s.get("file_path"),
            parser_hint=s.get("parser_hint"),
        ))
    return defs


def resolve_secret(cfg: Dict[str, Any], key: str) -> Optional[str]:
    """Resolve a credential from an environment variable named in config.
    The value never appears in config, logs, or events (Skill 08)."""
    env_name = cfg.get(key)
    if not env_name:
        return None
    value = os.environ.get(env_name)
    if value is None:
        raise ConfigError(
            f"environment variable {env_name} (for {key}) is not set"
        )
    return value
