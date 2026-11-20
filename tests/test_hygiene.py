"""Repository hygiene check: ensure zero secrets, VINs, serials, local paths, or raw binaries."""

from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Split literals avoid embedding sensitive tokens directly in test source.
FORBIDDEN_TOKENS = (
    "".join(["WF0GXX", "GBBGBD72065"]),
    "".join(["WF0DXX", "GBBD8C32912"]),
    "".join(["000816", "162490"]),
    "".join(["9214", "C0B2A3"]),
    "".join(["A3B2", "C01492"]),
    "".join(["A3 B2", " C0 14 92"]),
    "".join(["46F9", "DE3124"]),
    "".join(["2431", "DEF946"]),
    "".join(["24 31", " DE F9 46"]),
    "".join(["1050", "71BB"]),
    "".join(["20261120", "-104654"]),
    "".join(["20261120", "-150047"]),
    "".join(["/Users", "/"]),
    "".join(["file:", "///"]),
    "".join(["cal_", "builder"]),
)

FORBIDDEN_EXTS = {".bin", ".fls", ".vbf", ".epr", ".csv", ".rar", ".zip", ".xdf"}
TEXT_EXTS = {".py", ".md", ".toml", ".yml", ".yaml", ".txt", ".html", ".json"}


class TestRepoHygiene(unittest.TestCase):
    def test_no_forbidden_binaries_or_dumps(self) -> None:
        for path in REPO_ROOT.rglob("*"):
            if not path.is_file():
                continue
            if any(part.startswith(".") and part != ".github" for part in path.parts):
                continue
            if "__pycache__" in path.parts or "egg-info" in "".join(path.parts):
                continue
            self.assertNotIn(
                path.suffix.lower(),
                FORBIDDEN_EXTS,
                f"Forbidden binary/log/dump file present: {path}",
            )

    def test_no_secrets_vins_serials_or_local_paths(self) -> None:
        for path in REPO_ROOT.rglob("*"):
            if not path.is_file():
                continue
            if any(part.startswith(".") and part != ".github" for part in path.parts):
                continue
            if "__pycache__" in path.parts:
                continue
            if path.suffix.lower() not in TEXT_EXTS and path.name != "LICENSE":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            low = text.lower()
            for tok in FORBIDDEN_TOKENS:
                self.assertNotIn(
                    tok.lower(),
                    low,
                    f"Sensitive or disallowed token found in {path.relative_to(REPO_ROOT)}",
                )


if __name__ == "__main__":
    unittest.main()
