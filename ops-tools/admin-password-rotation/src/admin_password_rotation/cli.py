"""CLI for contract validation and read-only topology inspection."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .config import load_contract
from .errors import ReadError, SafeError
from .kubernetes import MAX_INVENTORY_BYTES, KubernetesReader, KubectlReader, SnapshotReader
from .planning import build_topology_plan
from .reporting import render_json, render_text


@dataclass
class Options(argparse.Namespace):
    command: str = ""
    contract: Path = Path(".")
    snapshot: str | None = None
    live: bool = False
    context: str | None = None
    kubeconfig: Path | None = None
    timeout: float = 60.0
    output_format: str = "text"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only credential topology inspector; never authorizes rotation.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-contract", help="Validate a contract without any cluster access")
    validate.add_argument("--contract", type=Path, required=True)
    plan = commands.add_parser("plan", help="Inspect topology; not a full transaction plan")
    plan.add_argument("--contract", type=Path, required=True)
    source = plan.add_mutually_exclusive_group(required=True)
    source.add_argument("--snapshot", help="SecretList JSON file, or - for stdin; never commit real snapshots")
    source.add_argument("--live", action="store_true", help="Explicitly allow a read from the named Kubernetes context")
    plan.add_argument("--context", help="Required with --live; no implicit current-context selection")
    plan.add_argument("--kubeconfig", type=Path)
    plan.add_argument("--timeout", type=float, default=60.0)
    plan.add_argument("--format", dest="output_format", choices=("text", "json"), default="text")
    return parser


def _snapshot(path: str) -> bytes:
    try:
        if path == "-":
            return sys.stdin.buffer.read(MAX_INVENTORY_BYTES + 1)
        with Path(path).open("rb") as handle:
            return handle.read(MAX_INVENTORY_BYTES + 1)
    except OSError:
        raise ReadError("snapshot_read", "Cannot read the snapshot file.") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    options = Options()
    parser.parse_args(None if argv is None else list(argv), namespace=options)
    try:
        # No network or subprocess access occurs before contract validation.
        contract = load_contract(options.contract)
        if options.command == "validate-contract":
            print(f"Contract valid: namespace={contract.namespace}; locations={len(contract.locations)}")
            return 0
        reader: KubernetesReader
        if options.live:
            if not options.context:
                raise ReadError("context_required", "--live requires an explicit --context.")
            reader = KubectlReader(context=options.context, kubeconfig=options.kubeconfig, timeout=options.timeout)
            mode = "live"
        else:
            if options.context is not None or options.kubeconfig is not None:
                raise ReadError("conflicting_input", "Context/kubeconfig flags are valid only with --live.")
            if options.snapshot is None:
                raise ReadError("input_required", "A snapshot or explicit live input is required.")
            reader = SnapshotReader(_snapshot(options.snapshot))
            mode = "snapshot"
        plan = build_topology_plan(contract, reader.list_secrets(contract.namespace), input_mode=mode)
        print(render_json(plan) if options.output_format == "json" else render_text(plan))
        return 0 if plan.topology_checks_passed else 3
    except SafeError as exc:
        # Parser and subprocess exceptions may contain entire secret documents.
        if options.command == "plan" and options.output_format == "json":
            print(json.dumps({"error": {"code": exc.code, "message": exc.message}, "rotation_ready": False}))
        else:
            print(str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 1
    except Exception:
        # Library calls can raise unforeseen exceptions with sensitive content.
        # Unit tests invoke individual functions directly for diagnostic tracebacks.
        print("internal_error: Unexpected failure; diagnostic content withheld.", file=sys.stderr)
        return 1
