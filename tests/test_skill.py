"""The bundled Claude skill (.claude/skills/iamai-review) ships in the public
repository and instructs a reader over real, unsanitised identity data.

These tests keep it honest: it must exist with valid frontmatter, carry no real
tenant or person identifier, only point at repository files that actually exist,
and keep the two load-bearing guardrails (confidentiality and do-not-re-grade)
in the text, so an edit cannot quietly drop them.
"""

import pathlib
import re

import pytest

pytestmark = pytest.mark.m13

ROOT = pathlib.Path(__file__).parents[1]
SKILL_DIR = ROOT / ".claude" / "skills" / "iamai-review"
SKILL = SKILL_DIR / "SKILL.md"
DATASETS = SKILL_DIR / "reference" / "datasets.md"


def test_skill_files_exist():
    assert SKILL.exists(), "SKILL.md is missing"
    assert DATASETS.exists(), "reference/datasets.md is missing"


def test_skill_has_valid_frontmatter():
    text = SKILL.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert match, "SKILL.md must open with a YAML frontmatter block"
    front = match.group(1)
    assert re.search(r"^name:\s*iamai-review\s*$", front, re.M)
    assert re.search(r"^description:\s*\S", front, re.M)


def test_skill_names_no_real_tenant_or_person():
    for path in (SKILL, DATASETS):
        low = path.read_text(encoding="utf-8").lower()
        for banned in ("onmicrosoft.com",):  # generic tenant-domain check; test_publication_safety.py is the full guard
            assert banned not in low, f"{banned} in {path.name}"


def test_skill_only_references_files_that_exist():
    """Every repository path the skill tells a reader to open must resolve, or
    the guidance sends them to a file that is not there."""
    text = SKILL.read_text(encoding="utf-8") + DATASETS.read_text(encoding="utf-8")
    referenced = {
        "ARTIFACTS.md": ROOT / "ARTIFACTS.md",
        "schemas/": ROOT / "schemas",
        "packs/": ROOT / "packs",
        "reference/datasets.md": DATASETS,
    }
    for token, target in referenced.items():
        assert token in text, f"expected the skill to reference {token}"
        assert target.exists(), f"{token} referenced but {target} does not exist"


def test_skill_keeps_its_guardrails():
    """The two rules the skill exists to enforce must stay in the text."""
    text = SKILL.read_text(encoding="utf-8").lower()
    # Confidentiality: the artifacts are real, unsanitised identity data.
    assert "not sanitised" in text or "unsanitised" in text
    assert "sanitize" in text  # points at the safe-sharing path
    # Do not re-grade: the engine is the only source of truth for grades.
    assert "never re-grade" in text or "never re-grade, override" in text
    assert "unknown" in text  # conservatism: UNKNOWN is not pass or fail
    # No invented single score.
    assert "no score" in text or "no percentage" in text
