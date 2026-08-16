"""The user guide (docs/guide.html) is generated from the shared theme and the
CLI itself.

These tests keep it honest: it must match what scripts/build_docs.py produces
(so it never drifts from the theme or the content), stay self-contained (GitHub
Pages serves it publicly and the tool's promise is no outbound traffic), name no
real tenant or person, and, crucially, mention every command the CLI actually
exposes, so the guide cannot silently fall behind the tool.
"""

import importlib.util
import pathlib
import sys

import pytest

pytestmark = pytest.mark.m13

ROOT = pathlib.Path(__file__).parents[1]
GUIDE = ROOT / "docs" / "guide.html"


def _build_module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _all_command_tokens():
    """Every leaf command as the user types it, e.g. 'collect', 'baseline build'."""
    sys.path.insert(0, str(ROOT / "src"))
    from typer.main import get_command

    from iamai.cli import app

    tokens: list[str] = []

    def walk(cmd, prefix=""):
        for name, sub in (getattr(cmd, "commands", None) or {}).items():
            if getattr(sub, "commands", None):
                walk(sub, f"{prefix}{name} ")
            else:
                tokens.append(f"{prefix}{name}".strip())

    walk(get_command(app))
    return tokens


def test_guide_matches_the_generator():
    """If this fails, run `python scripts/build_docs.py` and commit the result."""
    assert GUIDE.exists(), "docs/guide.html is missing; run scripts/build_docs.py"
    expected = _build_module("build_docs").render()
    assert GUIDE.read_text(encoding="utf-8") == expected, "docs/guide.html is stale; regenerate it"


def test_guide_documents_every_command():
    """The whole point of the guide: every function the tool exposes is in it."""
    html = GUIDE.read_text(encoding="utf-8")
    missing = [token for token in _all_command_tokens() if token not in html]
    assert not missing, f"commands absent from the guide: {missing}"


def test_guide_is_self_contained_and_shares_the_theme():
    from iamai.theme import BASE_CSS

    html = GUIDE.read_text(encoding="utf-8")
    assert "--brand:" in html and 'class="brandbar"' in html
    # No external asset of any kind (navigational https links are allowed).
    for external in ("<script", "<link ", "@import", "http://", "url("):
        assert external not in html, external
    assert "http" not in BASE_CSS
    # Command signatures with <alias> etc. must be escaped, not left as tags.
    assert "&lt;alias&gt;" in html
    assert "—" not in html  # no em dashes


def test_guide_names_no_real_tenant_or_person():
    low = GUIDE.read_text(encoding="utf-8").lower()
    for banned in ("onmicrosoft.com",):  # generic tenant-domain check; test_publication_safety.py is the full guard
        assert banned not in low, banned
