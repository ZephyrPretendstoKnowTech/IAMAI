"""PUB-M4: the skill walks a person through setup (SPEC-PUBLIC section 9).

The results-reading half of the skill is guarded by test_skill.py (m13, the
publication safety suite). This milestone adds the setup walkthrough, and
these tests keep it truthful: every command it names must exist in the CLI,
the path it teaches must be the real first-run path in the real order, and
the section 9 rules (the person runs the live commands; the collector is
usable without the skill) must stay in the text.
"""

import pathlib
import re

import pytest

pytestmark = pytest.mark.m14

ROOT = pathlib.Path(__file__).parents[1]
SKILL_DIR = ROOT / ".claude" / "skills" / "iamai-review"
SKILL = SKILL_DIR / "SKILL.md"
SETUP = SKILL_DIR / "reference" / "setup.md"
DATASETS = SKILL_DIR / "reference" / "datasets.md"


def cli_command_names() -> set[str]:
    from iamai import cli

    names = {c.name or c.callback.__name__ for c in cli.app.registered_commands}
    names |= {g.name for g in cli.app.registered_groups}
    return {str(n) for n in names}


def test_the_walkthrough_exists_and_is_wired_in():
    assert SETUP.exists(), "reference/setup.md is missing"
    text = SKILL.read_text(encoding="utf-8")
    assert "reference/setup.md" in text, "SKILL.md must point at the walkthrough"
    # The frontmatter description must trigger on setup questions, or the
    # walkthrough exists but is never reached.
    front = re.match(r"^---\n(.*?)\n---\n", text, re.S).group(1)
    assert "setup" in front.lower()


def test_every_command_the_skill_names_is_real():
    """A walkthrough that names a command the CLI does not have sends a new
    user to an error message as their first experience."""
    real = cli_command_names()
    for path in (SKILL, SETUP, DATASETS):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"iamai ([a-z]+)", text):
            assert match.group(1) in real, f"{path.name} names 'iamai {match.group(1)}'"


def test_the_walkthrough_teaches_the_real_path_in_order():
    """Install, setup, consent, verify, collect, assess, wizard, plan. Out of
    order is worse than absent: enforcing before enrolling is the exact
    failure mode the tool exists to prevent, and a walkthrough that grades
    before collecting has the same shape."""
    text = SETUP.read_text(encoding="utf-8").lower()
    numbers = [int(n) for n in re.findall(r"^## (\d+)\.", text, re.M)]
    assert numbers == list(range(1, len(numbers) + 1)), numbers
    sections = re.split(r"^## \d+\.", text, flags=re.M)[1:]
    stations = ["install", "iamai setup", "consent", "iamai verify",
                "iamai collect", "iamai assess", "iamai wizard", "iamai plan"]
    assert len(sections) >= len(stations)
    for station, section in zip(stations, sections):
        assert station in section, f"step for {station!r} out of place"


def test_the_install_one_liners_point_at_scripts_that_exist():
    text = SETUP.read_text(encoding="utf-8")
    for script in ("scripts/install.ps1", "scripts/install.sh"):
        assert script in text, f"walkthrough must carry the {script} one-liner"
        assert (ROOT / script).exists(), f"{script} referenced but missing"


def test_the_section_9_rules_stay_in_the_text():
    """SPEC-PUBLIC section 9: the skill is a better front door, not a
    dependency, and the live commands are the person's to run."""
    combined = (SKILL.read_text(encoding="utf-8") + SETUP.read_text(encoding="utf-8")).lower()
    assert "usable without" in combined or "fully usable without" in combined
    assert "they run every command" in combined
    assert "read-only" in combined or "read only" in combined


def test_the_walkthrough_names_no_real_tenant_or_person():
    low = SETUP.read_text(encoding="utf-8").lower()
    assert "onmicrosoft.com" not in low
    assert not re.search(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", low
    ), "no GUID belongs in the walkthrough; tenant ids are the reader's own"
