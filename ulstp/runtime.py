"""Runtime wiring (build plan §9, §31, §36): config → pipeline → collectors →
delivery manager → API. Used by the CLI `run` command and tests."""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from .api import ApiServer
from .collectors import CollectorStage, FileCollector, TcpCollector, UdpCollector
from .config import resolve_secret
from .delivery import (
    DeliveryManager, ElasticTarget, QradarTarget, SpoolTarget, SyslogTarget,
)
from .errors import ConfigError
from .limits import ResourceLimits
from .metrics import Metrics
from .pipeline import Pipeline
from .source_id import SourceDefinition, SourceIdentifier


class Runtime:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self.limits: ResourceLimits = (
            ResourceLimits(**cfg["limits"]) if "limits" in cfg else ResourceLimits()
        )
        self.metrics = Metrics()
        source_defs = [
            SourceDefinition(
                source_id=s["source_id"],
                vendor=s.get("vendor"),
                product=s.get("product"),
                transport=s.get("transport"),
                peer_ip=s.get("peer_ip"),
                local_port=s.get("port"),
                file_path=s.get("file_path"),
                parser_hint=s.get("parser_hint"),
            )
            for s in cfg.get("sources", [])
        ]
        self.pipeline = Pipeline(
            limits=self.limits,
            source_definitions=source_defs,
            metrics=self.metrics,
        )
        self.collectors: List[Any] = []
        self.delivery: Optional[DeliveryManager] = None
        self.api: Optional[ApiServer] = None

    # ------------------------------------------------------------------ components
    def build_collectors(self) -> None:
        for spec in self.cfg.get("listeners", []):
            t = spec["type"]
            if t == "udp":
                c = UdpCollector(self.pipeline.stage, host=spec.get("host", "0.0.0.0"),
                                 port=spec.get("port", 5514), limits=self.limits)
            elif t == "tcp":
                c = TcpCollector(self.pipeline.stage, host=spec.get("host", "0.0.0.0"),
                                 port=spec.get("port", 5601), limits=self.limits)
            elif t == "file":
                c = FileCollector(self.pipeline.stage, path=spec["path"],
                                  follow=spec.get("follow", False), limits=self.limits)
            else:  # validated earlier, defensive
                raise ConfigError(f"unknown listener type {t!r}")
            self.collectors.append(c)

    def build_delivery(self) -> None:
        siem = self.cfg.get("siem")
        if not siem:
            return
        stype = siem["type"]
        spool = SpoolTarget(siem.get("spool_path", "ulstp-spool.jsonl"))
        if stype == "spool":
            target = SpoolTarget(siem["path"])
            spool = target  # spool fallback = same target
        elif stype == "syslog":
            target = SyslogTarget(siem["host"], siem["port"],
                                  transport=siem.get("transport", "udp"),
                                  tag=siem.get("tag", "ulstp"),
                                  pri=siem.get("pri", 134))
        elif stype == "qradar":
            target = QradarTarget(siem["host"], siem["port"],
                                  transport=siem.get("transport", "tcp"))
        elif stype == "elastic":
            api_key = resolve_secret(siem, "api_key_env")
            target = ElasticTarget(siem["url"],
                                   index_prefix=siem.get("index_prefix", "ulstp"),
                                   api_key=api_key)
        else:
            raise ConfigError(f"unknown siem type {stype!r}")
        self.delivery = DeliveryManager(
            target, spool, self.limits, self.metrics,
            batch_size=siem.get("batch_size", 100),
            flush_interval=siem.get("flush_interval", 1.0),
        )
        self.pipeline.sink = self.delivery.submit

    def build_api(self) -> None:
        api_cfg = self.cfg.get("api", {})
        if api_cfg.get("enabled", True):
            self.api = ApiServer(self.pipeline,
                                 host=api_cfg.get("host", "127.0.0.1"),
                                 port=api_cfg.get("port", 8080))

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.pipeline.start()
        for c in self.collectors:
            c.start()
        if self.delivery:
            self.delivery.start()
        if self.api:
            self.api.start()

    def stop(self) -> None:
        for c in self.collectors:
            c.stop()
        if self.delivery:
            self.delivery.stop(flush=True)
        if self.api:
            self.api.stop()
        self.pipeline.stop()

    def wait_forever(self) -> None:
        threading.Event().wait()
