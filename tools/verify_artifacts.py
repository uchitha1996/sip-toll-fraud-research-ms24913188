"""Verify imported research bytes without executing laboratory code."""
from pathlib import Path
import hashlib
import json
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    records = json.loads((root / "FILE_MANIFEST.json").read_text(encoding="utf-8-sig"))
    imported_count = len(records)
    thesis_manifest = root / "documents/final/FILES.json"
    if thesis_manifest.is_file():
        records.extend(json.loads(thesis_manifest.read_text(encoding="utf-8-sig")))
    failures = []
    seen = set()
    for record in records:
        relative = record["path"]
        path = (root / relative).resolve()
        if root not in path.parents or relative in seen:
            failures.append(f"Invalid or duplicate manifest path: {relative}")
            continue
        seen.add(relative)
        if not path.is_file():
            failures.append(f"Missing: {relative}")
            continue
        data = path.read_bytes()
        if len(data) != record["bytes"]:
            failures.append(f"Size mismatch: {relative}")
        if hashlib.sha256(data).hexdigest() != record["sha256"]:
            failures.append(f"SHA-256 mismatch: {relative}")
    if failures:
        print("\n".join(failures))
        print(f"FAILED: {len(failures)} integrity checks")
        return 1
    print(f"PASS: {imported_count} imported artifacts and {len(records)-imported_count} current thesis files match their recorded sizes and SHA-256 hashes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
