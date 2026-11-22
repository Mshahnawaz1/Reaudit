from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from . import run_deterministic


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m backend.app.deterministic <dir>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    hits, warnings = asyncio.run(run_deterministic(root))
    print(json.dumps({"hits": [h.model_dump() for h in hits], "warnings": warnings}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
