"""The public demo page (docs/index.html) is generated from the shared theme.

These tests keep it honest: it must match what scripts/build_demo.py produces
(so it never drifts from the theme), stay self-contained (GitHub Pages serves
it to the public, and the whole tool's promise is no outbound traffic), and
never embed a real tenant or repository name.
"""

import importlib.util
import pathlib

import pytest

pytestmark = pytest.mark.m13

ROOT = pathlib.Path(__file__).parents[1]
DOCS = ROOT / "docs" / "index.html"
EXAMPLE = ROOT / "docs" / "example-report.html"
USECASES = ROOT / "docs" / "use-cases.html"


def _build_module(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "scripts" / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_page_matches_the_generator():
    """If this fails, run `python scripts/build_demo.py` and commit the result;
    the committed page has drifted from the theme or the copy."""
    assert DOCS.exists(), "docs/index.html is missing; run scripts/build_demo.py"
    expected = _build_module("build_demo").render()
    actual = DOCS.read_text(encoding="utf-8")
    assert actual == expected, "docs/index.html is stale; regenerate it"


def test_demo_page_shares_the_theme_and_is_self_contained():
    from iamai.theme import BASE_CSS

    html = DOCS.read_text(encoding="utf-8")
    # Same design foundation as the app pages.
    assert "--brand:" in html and 'class="brandbar"' in html
    assert "ol.actions > li" in html and "&gt; li" not in html
    # No external asset of any kind: GitHub Pages serves this publicly and the
    # tool's whole promise is that its pages make no outbound request.
    for external in ("<script", "<link ", "@import", "http://", "url("):
        assert external not in html, external
    # BASE_CSS itself must carry no external reference.
    assert "http" not in BASE_CSS


def test_demo_page_names_no_real_tenant_or_person():
    """It publishes with the repository, so it must be clean of anything that
    identifies a real tenant, person, or development-time identifier."""
    html = DOCS.read_text(encoding="utf-8").lower()
    for banned in ("onmicrosoft.com",):  # generic tenant-domain check; test_publication_safety.py is the full guard
        assert banned not in html, banned


def test_use_cases_page_matches_and_is_clean():
    """The value page publishes with the repository: it must match its generator,
    load nothing external, name no real identifier, and be reachable from the
    landing page. It is illustrative marketing, so it must also not fabricate a
    named customer or a metric dressed up as real."""
    assert USECASES.exists(), "docs/use-cases.html is missing; run scripts/build_usecases.py"
    html = _build_module("build_usecases").render()
    assert USECASES.read_text(encoding="utf-8") == html, "use-cases page is stale; regenerate it"
    assert 'class="brandbar"' in html and "--brand:" in html
    for external in ("<script", "<link ", "@import", "http://", "url("):
        assert external not in html, external
    for banned in ("onmicrosoft.com",):  # generic tenant-domain check; test_publication_safety.py is the full guard
        assert banned not in html.lower(), banned
    assert "—" not in html  # no em dashes
    assert "use-cases.html" in DOCS.read_text(encoding="utf-8"), "landing page must link to it"


def test_example_report_matches_the_generator():
    """The published sample is a real assessment rendered from the sanitized
    fixture. Regenerate with scripts/build_example_report.py if this fails."""
    assert EXAMPLE.exists(), "docs/example-report.html is missing"
    expected = _build_module("build_example_report").render()
    assert EXAMPLE.read_text(encoding="utf-8") == expected, "example report is stale; regenerate it"


def test_example_report_is_clean_and_self_contained():
    """It is published, so it must expose no real identity and load nothing
    external. The fixture behind it is sanitized: every name is a stand in."""
    html = EXAMPLE.read_text(encoding="utf-8")
    low = html.lower()
    for banned in ("onmicrosoft.com",):  # generic tenant-domain check; test_publication_safety.py is the full guard
        assert banned not in low, banned
    for external in ("<script", "<link ", "@import", "http://", "https://"):
        assert external not in html, external
    # It is a real assessment, so it should carry graded controls and the shared theme.
    assert 'class="grade' in html and 'class="brandbar"' in html
    # The demo page points at it.
    assert "example-report.html" in DOCS.read_text(encoding="utf-8")
