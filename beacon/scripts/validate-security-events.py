#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Validate JSONL Security events against the pinned language-neutral schema."""

import argparse
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, nargs="+", help="UTF-8 JSONL event files")
    args = parser.parse_args()
    schema_path = Path(__file__).resolve().parents[1] / "security" / "beacon-security-event-v2.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    count = 0
    failed = False
    for path in args.events:
        with path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                count += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    print(f"{path}:{line_number}: invalid JSON", file=sys.stderr)
                    failed = True
                    continue
                for error in validator.iter_errors(record):
                    # Report locations and rules without dumping potentially sensitive input.
                    location = "/".join(str(part) for part in error.absolute_schema_path)
                    print(f"{path}:{line_number}: schema violation at {location}", file=sys.stderr)
                    failed = True
    if not count:
        print("No events were provided.", file=sys.stderr)
        return 1
    if failed:
        return 1
    print(f"Validated {count} Security events against schema v2.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
