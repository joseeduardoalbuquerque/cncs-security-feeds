#!/usr/bin/env python3
"""Validate, update and build the public CNCS IP feed."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = ROOT / "data" / "cncs_indicators.json"
DEFAULT_FEED = ROOT / "feeds" / "blacklist_cncs.txt"
DEFAULT_INBOX = ROOT / "incoming" / "cncs.txt"
INBOX_TEMPLATE = (
    "# Cole aqui os IPs ou CIDR recebidos do CNCS, um por linha.\n"
    "# O workflow limpa este ficheiro depois de uma importação bem-sucedida.\n"
)
TOKEN_SPLIT = re.compile(r"[\s,;]+")


class FeedError(ValueError):
    """Raised when an input or stored feed is invalid."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FeedError(f"Invalid ISO 8601 timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise FeedError("Timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def clean_source_ref(value: str) -> str:
    cleaned = " ".join(value.split())
    if len(cleaned) > 200:
        raise FeedError("Source reference cannot exceed 200 characters")
    return cleaned or "CNCS notification"


def normalise_indicator(value: str, allow_non_global: bool = False) -> tuple[str, int, str]:
    candidate = value.strip()
    if not candidate:
        raise FeedError("Empty indicator")
    try:
        if "/" in candidate:
            network = ipaddress.ip_network(candidate, strict=False)
            if network.prefixlen == network.max_prefixlen:
                address = network.network_address
                canonical = address.compressed
                kind = "ip"
                is_global = address.is_global
            else:
                canonical = network.with_prefixlen
                kind = "cidr"
                is_global = network.is_global
            version = network.version
        else:
            address = ipaddress.ip_address(candidate)
            canonical = address.compressed
            kind = "ip"
            is_global = address.is_global
            version = address.version
    except ValueError as exc:
        raise FeedError(f"Invalid IP or CIDR: {candidate}") from exc

    if not allow_non_global and not is_global:
        raise FeedError(f"Non-global indicator rejected: {canonical}")
    return canonical, version, kind


def parse_indicators(text: str, allow_non_global: bool = False) -> list[tuple[str, int, str]]:
    values: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            values.extend(token for token in TOKEN_SPLIT.split(line) if token)

    result: dict[str, tuple[str, int, str]] = {}
    errors: list[str] = []
    for value in values:
        try:
            item = normalise_indicator(value, allow_non_global=allow_non_global)
            result[item[0]] = item
        except FeedError as exc:
            errors.append(str(exc))
    if errors:
        raise FeedError("\n".join(errors))
    return list(result.values())


def read_inputs(paths: Iterable[Path], allow_non_global: bool = False) -> list[tuple[str, int, str]]:
    parsed: dict[str, tuple[str, int, str]] = {}
    for path in paths:
        if not path.is_file():
            raise FeedError(f"Input file not found: {path}")
        for item in parse_indicators(path.read_text(encoding="utf-8"), allow_non_global):
            parsed[item[0]] = item
    return list(parsed.values())


def empty_database() -> dict[str, Any]:
    return {"schema_version": 1, "indicators": {}}


def load_database(path: Path) -> dict[str, Any]:
    if not path.exists():
        return empty_database()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise FeedError(f"Cannot read database {path}: {exc}") from exc
    if data.get("schema_version") != 1 or not isinstance(data.get("indicators"), dict):
        raise FeedError("Unsupported or invalid indicator database")
    return data


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def save_database(path: Path, data: dict[str, Any]) -> None:
    ordered = {
        "schema_version": 1,
        "indicators": {key: data["indicators"][key] for key in sorted_indicators(data["indicators"])},
    }
    atomic_write(path, json.dumps(ordered, ensure_ascii=False, indent=2) + "\n")


def indicator_sort_key(value: str) -> tuple[int, int, int]:
    if "/" in value:
        item = ipaddress.ip_network(value, strict=False)
        return item.version, int(item.network_address), item.prefixlen
    item = ipaddress.ip_address(value)
    return item.version, int(item), item.max_prefixlen


def sorted_indicators(values: Iterable[str]) -> list[str]:
    return sorted(values, key=indicator_sort_key)


def build_feed(data: dict[str, Any], feed_path: Path) -> int:
    active = [key for key, record in data["indicators"].items() if record.get("status") == "active"]
    content = "".join(f"{indicator}\n" for indicator in sorted_indicators(active))
    atomic_write(feed_path, content)
    return len(active)


def apply_operation(
    operation: str,
    items: Iterable[tuple[str, int, str]],
    database_path: Path,
    feed_path: Path,
    source_ref: str,
    observed_at: str,
) -> dict[str, int]:
    data = load_database(database_path)
    source = clean_source_ref(source_ref)
    timestamp = validate_timestamp(observed_at)
    added = reactivated = removed = unchanged = 0

    for indicator, version, kind in items:
        record = data["indicators"].get(indicator)
        if operation == "add":
            if record is None:
                record = {
                    "first_seen": timestamp,
                    "ip_version": version,
                    "kind": kind,
                    "last_seen": timestamp,
                    "removed_at": None,
                    "source_refs": [source],
                    "status": "active",
                }
                data["indicators"][indicator] = record
                added += 1
            else:
                if record.get("status") != "active":
                    reactivated += 1
                else:
                    unchanged += 1
                record["status"] = "active"
                record["last_seen"] = timestamp
                record["removed_at"] = None
                refs = record.setdefault("source_refs", [])
                if source not in refs:
                    refs.append(source)
        elif operation == "remove":
            if record is None or record.get("status") != "active":
                unchanged += 1
                continue
            record["status"] = "inactive"
            record["removed_at"] = timestamp
            refs = record.setdefault("source_refs", [])
            if source not in refs:
                refs.append(source)
            removed += 1
        else:
            raise FeedError(f"Unsupported operation: {operation}")

    save_database(database_path, data)
    active = build_feed(data, feed_path)
    return {"added": added, "reactivated": reactivated, "removed": removed, "unchanged": unchanged, "active": active}


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def process_event(args: argparse.Namespace) -> dict[str, int]:
    try:
        event = json.loads(args.event_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise FeedError(f"Cannot read GitHub event: {exc}") from exc

    if isinstance(event.get("client_payload"), dict):
        payload = event["client_payload"]
        default_source = "CNCS automated integration"
    elif isinstance(event.get("inputs"), dict):
        payload = event["inputs"]
        default_source = "GitHub manual workflow"
    else:
        items = read_inputs([args.inbox], allow_non_global=False)
        result = apply_operation(
            "add", items, args.database, args.feed, "GitHub inbox update", utc_now()
        )
        atomic_write(args.inbox, INBOX_TEMPLATE)
        return result

    raw_indicators = payload.get("indicators", "")
    if isinstance(raw_indicators, list):
        raw_indicators = "\n".join(str(value) for value in raw_indicators)
    if not isinstance(raw_indicators, str):
        raise FeedError("The indicators payload must be a string or a list")
    allow_non_global = bool_value(payload.get("allow_non_global", False))
    items = parse_indicators(raw_indicators, allow_non_global=allow_non_global)
    if not items:
        raise FeedError("No indicators were supplied")
    return apply_operation(
        str(payload.get("operation", "add")),
        items,
        args.database,
        args.feed,
        str(payload.get("source_ref", default_source)),
        str(payload.get("observed_at", utc_now())),
    )


def validate_repository(database_path: Path, feed_path: Path) -> dict[str, int]:
    data = load_database(database_path)
    errors: list[str] = []
    for key, record in data["indicators"].items():
        try:
            canonical, version, kind = normalise_indicator(key, allow_non_global=True)
            if canonical != key:
                errors.append(f"Non-canonical indicator key: {key}")
            if record.get("ip_version") != version or record.get("kind") != kind:
                errors.append(f"Incorrect metadata for {key}")
            if record.get("status") not in {"active", "inactive"}:
                errors.append(f"Invalid status for {key}")
            validate_timestamp(record.get("first_seen", ""))
            validate_timestamp(record.get("last_seen", ""))
            if not isinstance(record.get("source_refs"), list) or not record["source_refs"]:
                errors.append(f"Missing source reference for {key}")
        except FeedError as exc:
            errors.append(f"{key}: {exc}")

    expected = "".join(
        f"{indicator}\n"
        for indicator in sorted_indicators(
            key for key, record in data["indicators"].items() if record.get("status") == "active"
        )
    )
    actual = feed_path.read_text(encoding="utf-8") if feed_path.exists() else ""
    if actual != expected:
        errors.append("Generated feed does not match the active indicator database")
    if errors:
        raise FeedError("\n".join(errors))
    return {"records": len(data["indicators"]), "active": expected.count("\n")}


def add_common_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--feed", type=Path, default=DEFAULT_FEED)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    for operation in ("add", "remove"):
        action = subparsers.add_parser(operation, help=f"{operation.title()} indicators")
        add_common_paths(action)
        action.add_argument("--input", type=Path, action="append", required=True)
        action.add_argument("--source-ref", default="CNCS notification")
        action.add_argument("--observed-at", default=None)
        action.add_argument("--allow-non-global", action="store_true")

    event = subparsers.add_parser("event", help="Process a GitHub event payload")
    add_common_paths(event)
    event.add_argument("--event-json", type=Path, required=True)
    event.add_argument("--inbox", type=Path, default=DEFAULT_INBOX)

    validate = subparsers.add_parser("validate", help="Validate database and generated feed")
    add_common_paths(validate)

    check_input = subparsers.add_parser("check-input", help="Validate an input file without changing the feed")
    check_input.add_argument("--input", type=Path, action="append", required=True)
    check_input.add_argument("--allow-non-global", action="store_true")

    build = subparsers.add_parser("build", help="Rebuild the text feed from the database")
    add_common_paths(build)
    return parser


def main() -> int:
    args = create_parser().parse_args()
    try:
        if args.command in {"add", "remove"}:
            items = read_inputs(args.input, allow_non_global=args.allow_non_global)
            if not items:
                raise FeedError("No indicators were supplied")
            result = apply_operation(
                args.command,
                items,
                args.database,
                args.feed,
                args.source_ref,
                args.observed_at or utc_now(),
            )
        elif args.command == "event":
            result = process_event(args)
        elif args.command == "validate":
            result = validate_repository(args.database, args.feed)
        elif args.command == "check-input":
            items = read_inputs(args.input, allow_non_global=args.allow_non_global)
            result = {"valid": len(items)}
        elif args.command == "build":
            data = load_database(args.database)
            result = {"active": build_feed(data, args.feed)}
        else:
            raise FeedError(f"Unknown command: {args.command}")
    except FeedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
