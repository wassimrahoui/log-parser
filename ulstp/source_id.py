"""Source identification (build plan §20; Skill 04).

Deterministic and explainable. Evidence is collected in a fixed priority
order; the first deterministic hit determines the result class:

  1. configured source definition (transport+peer / file path)  -> KNOWN
  2. message signature (vendor/product signature table)          -> INFERRED
  3. protocol identifiers (RFC5424 appname, CEF/LEEF header)     -> INFERRED
  4. transport metadata only                                     -> UNKNOWN

No probabilistic scoring; no certainty invention. Unknown sources are valid.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .event import LosslessEvent, SourceStatus

Evidence = Tuple[str, str]


@dataclass
class SourceDefinition:
    """Configured source (Skill 04: explicit config outranks signatures)."""
    source_id: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    transport: Optional[str] = None          # "udp" | "tcp" | "file"
    peer_ip: Optional[str] = None            # exact match when set
    local_port: Optional[int] = None         # exact match when set
    file_path: Optional[str] = None          # exact match when set
    parser_hint: Optional[str] = None


@dataclass
class SourceIdentification:
    status: str = SourceStatus.UNKNOWN.value
    source_id: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    parser_hint: Optional[str] = None
    confidence_source: str = "none"          # configured | signature | protocol | none
    evidence: List[Evidence] = field(default_factory=list)


# Signature table: (name, compiled regex on message, vendor, product)
# Order matters: first match wins (deterministic). Only signatures backed by
# research records (docs/research/) appear here — never invented.
_SIGNATURES: List[Tuple[str, "re.Pattern[str]", str, str]] = [
    (r"sig_cisco_asa", re.compile(r"%ASA-\d-\d+:"), "Cisco", "ASA"),
    (r"sig_cisco_pix", re.compile(r"%PIX-\d-\d+:"), "Cisco", "PIX"),
    (r"sig_cisco_fwsm", re.compile(r"%FWSM-\d-\d+:"), "Cisco", "FWSM"),
    (r"sig_cisco_asdm", re.compile(r"%ASDM-\d-\d+:"), "Cisco", "ASDM"),
    (r"sig_fortigate", re.compile(r"\blogid=\d{10}\b.*\btype=\w+.*\bsubtype=\w+", re.S),
     "Fortinet", "FortiGate"),
    (r"sig_sonicwall", re.compile(r"\bid=firewall\b.*\bsn=\w+.*\bfw=\d+\.\d+\.\d+\.\d+", re.S),
     "SonicWall", "Firewall"),
]


@dataclass
class SourceIdentifier:
    definitions: List[SourceDefinition] = field(default_factory=list)

    def identify(self, event: LosslessEvent) -> SourceIdentification:
        evidence: List[Evidence] = []
        raw = event.raw_message or ""
        ident = SourceIdentification(evidence=evidence)

        # transport evidence always recorded (explainability, Skill 04)
        if event.transport:
            evidence.append(("transport", event.transport))
        if event.transport_protocol:
            evidence.append(("protocol", event.transport_protocol))
        if event.peer_ip is not None:
            evidence.append(("peer", event.peer_ip))
        if event.local_port is not None:
            evidence.append(("port", str(event.local_port)))
        if event.file_path is not None:
            evidence.append(("file", event.file_path))

        # 1) configured definitions (deterministic exact matches)
        for d in self.definitions:
            if self._matches_definition(d, event):
                evidence.append(("configured_source", d.source_id))
                if d.parser_hint:
                    evidence.append(("parser_hint", d.parser_hint))
                ident.status = SourceStatus.KNOWN.value
                ident.source_id = d.source_id
                ident.vendor = d.vendor
                ident.product = d.product
                ident.parser_hint = d.parser_hint
                ident.confidence_source = "configured"
                return ident

        # 2) message signatures
        for name, pattern, vendor, product in _SIGNATURES:
            m = pattern.search(raw)
            if m:
                evidence.append(("signature", name))
                evidence.append(("signature_match", m.group(0)[:80]))
                ident.status = SourceStatus.INFERRED.value
                ident.vendor = vendor
                ident.product = product
                ident.confidence_source = "signature"
                return ident

        # 3) protocol identifiers from decoded representation
        vendor = None
        product = None
        decoded = event.decoded or {}
        fmt = event.format_detected or ""
        if fmt == "cef":
            vendor = decoded.get("cef_device_vendor")
            product = decoded.get("cef_device_product")
            if vendor:
                evidence.append(("cef_header", f"{vendor}|{product or ''}"))
        elif fmt == "leef":
            vendor = decoded.get("leef_vendor")
            product = decoded.get("leef_product")
            if vendor:
                evidence.append(("leef_header", f"{vendor}|{product or ''}"))
        elif fmt == "rfc5424":
            appname = decoded.get("appname")
            if appname and appname != "-":
                evidence.append(("rfc5424.appname", appname))
                product = appname
        elif fmt == "rfc3164":
            tag = decoded.get("tag")
            if tag:
                evidence.append(("rfc3164.tag", tag))
                product = tag
        if vendor:
            ident.status = SourceStatus.INFERRED.value
            ident.vendor = vendor
            ident.product = product
            ident.confidence_source = "protocol"
            return ident

        # 4) unknown — still a valid event (§12)
        ident.status = SourceStatus.UNKNOWN.value
        ident.confidence_source = "none"
        evidence.append(("result", "no deterministic rule matched"))
        return ident

    @staticmethod
    def _matches_definition(d: SourceDefinition, event: LosslessEvent) -> bool:
        if d.transport and event.transport != d.transport:
            return False
        if d.peer_ip and event.peer_ip != d.peer_ip:
            return False
        if d.local_port is not None and event.local_port != d.local_port:
            return False
        if d.file_path and event.file_path != d.file_path:
            return False
        # at least one anchor must be present to avoid matching everything
        return bool(d.peer_ip or d.local_port is not None or d.file_path or d.transport)
