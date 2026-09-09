"""CLI (build plan §26): run, parse, replay, test-parser, metrics.

Examples:
    python -m ulstp.cli run --config config.json
    python -m ulstp.cli parse "<134>1 2026-09-09T12:00:00Z h a 1 ID - msg"
    python -m ulstp.cli replay samples.txt
    python -m ulstp.cli test-parser cef --input message.txt
    python -m ulstp.cli serve --api-port 8080   # pipeline + API, no listeners
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .config import load_config, validate_config
from .errors import UlstpError
from .pipeline import Pipeline


def _print_event(ev) -> None:
    print(json.dumps(ev.dict_event(), ensure_ascii=False, indent=1))


def cmd_run(args) -> int:
    from .runtime import Runtime

    cfg = load_config(args.config)
    runtime = Runtime(cfg)
    runtime.build_collectors()
    runtime.build_delivery()
    runtime.build_api()
    runtime.start()
    print(f"ULSTP v{__version__} running. Ctrl+C to stop.", file=sys.stderr)
    if runtime.api:
        print(f"  API/UI: http://{runtime.api.host}:{runtime.api.port}/", file=sys.stderr)
    for c in runtime.collectors:
        kind = type(c).__name__.replace("Collector", "").lower()
        print(f"  collector: {kind}", file=sys.stderr)
    if runtime.delivery:
        print(f"  siem: {runtime.delivery.target.name}", file=sys.stderr)
    try:
        runtime.wait_forever()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
    return 0


def cmd_parse(args) -> int:
    pipeline = Pipeline()
    raw = args.input if args.input else sys.stdin.read()
    if not raw:
        print("no input", file=sys.stderr)
        return 2
    ev = pipeline.process_text(raw)
    _print_event(ev)
    return 0


def cmd_replay(args) -> int:
    """Replay saved raw telemetry through the real pipeline (deterministic)."""
    from .runtime import Runtime

    cfg = load_config(args.config) if args.config else {}
    runtime = Runtime(cfg)
    runtime.build_api() if args.api else None
    runtime.pipeline.start()
    with open(args.file, "r", encoding="utf-8", errors="surrogateescape") as fh:
        lines = [line.rstrip("\n") for line in fh]
    runtime.pipeline.replay.replay(lines)
    if not runtime.pipeline.wait_until_drained(timeout=30):
        print("warning: replay did not drain in time", file=sys.stderr)
    import time
    time.sleep(0.2)
    for ev in runtime.pipeline.history():
        if args.summary:
            print(f"{ev.event_id[:8]}  {str(ev.format_detected):<12} "
                  f"{str(ev.source_status):<8} {str(ev.vendor):<10} "
                  f"{str(ev.parser_name):<22} {ev.parse_status}")
        else:
            _print_event(ev)
    runtime.stop()
    return 0


def cmd_test_parser(args) -> int:
    from .registry import ParserRegistry

    registry = ParserRegistry()
    names = [p.name for p in registry.parsers]
    if args.parser and args.parser not in names:
        print(f"unknown parser {args.parser!r}; available: {names}", file=sys.stderr)
        return 2
    raw = args.input if args.input else sys.stdin.read()
    matched = []
    for parser in registry.parsers:
        if args.parser and parser.name != args.parser:
            continue
        if parser.accept(raw):
            matched.append(parser)
    if not matched:
        print("no parser accepted this input (raw preserved as fallback)", file=sys.stderr)
        return 1
    for parser in matched:
        result = parser.parse(raw)
        print(f"# parser={parser.name} version={parser.version} status={result.status}")
        print(json.dumps({
            "fields": result.fields,
            "vendor_fields": result.vendor_fields,
            "unknown_fields": result.unknown_fields,
            "originals": result.originals,
            "decoded": result.decoded,
            "notes": result.notes,
        }, ensure_ascii=False, indent=1))
    return 0


def cmd_metrics(args) -> int:
    """Print metrics snapshot (operational observability, §40)."""
    pipeline = Pipeline()
    print(json.dumps(pipeline.metrics.snapshot(), indent=1))
    return 0


def cmd_serve(args) -> int:
    """Pipeline + API without network listeners (inspection sandbox)."""
    from .runtime import Runtime

    runtime = Runtime({})
    runtime.build_api()
    runtime.api.port = args.api_port
    runtime.start()
    print(f"ULSTP v{__version__} sandbox at http://127.0.0.1:{runtime.api.port}/ "
          f"(POST /api/parse to inspect events)", file=sys.stderr)
    try:
        runtime.wait_forever()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="ulstp",
        description="Universal Lossless SIEM Telemetry Platform "
                    "(deterministic, AI-free, lossless)",
    )
    ap.add_argument("--version", action="version", version=f"ulstp {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run collectors, pipeline, delivery, API")
    p_run.add_argument("--config", required=True)
    p_run.set_defaults(func=cmd_run)

    p_parse = sub.add_parser("parse", help="parse one message, print lossless event")
    p_parse.add_argument("input", nargs="?", help="raw telemetry (default: stdin)")
    p_parse.set_defaults(func=cmd_parse)

    p_replay = sub.add_parser("replay", help="replay a file of raw messages")
    p_replay.add_argument("file")
    p_replay.add_argument("--config", help="optional config for source definitions")
    p_replay.add_argument("--summary", action="store_true")
    p_replay.add_argument("--api", action="store_true", help="also start API/UI")
    p_replay.set_defaults(func=cmd_replay)

    p_tp = sub.add_parser("test-parser", help="check which parser accepts an input")
    p_tp.add_argument("parser", nargs="?", help="parser name (default: all)")
    p_tp.add_argument("--input", help="raw message (default: stdin)")
    p_tp.set_defaults(func=cmd_test_parser)

    p_serve = sub.add_parser("serve", help="run API/UI sandbox without listeners")
    p_serve.add_argument("--api-port", type=int, default=8080)
    p_serve.set_defaults(func=cmd_serve)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except UlstpError as exc:
        print(f"error [{getattr(exc, 'code', 'ULSTP_ERROR')}]: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
