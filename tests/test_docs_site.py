"""The published docs pages cross-link each other (landing, use cases, guide,
sample report). A dead internal link is exactly the kind of thing that shows up
in a demo, so this checks every one resolves, and that the pages agree on a
single repository URL rather than drifting apart.
"""

import pathlib
import re

import pytest

pytestmark = pytest.mark.m13

DOCS = pathlib.Path(__file__).parents[1] / "docs"


def _internal_hrefs(html: str):
    for href in re.findall(r'href="([^"]+)"', html):
        if href.startswith(("http://", "https://", "mailto:", "#")):
            continue
        yield href


def test_every_internal_docs_link_resolves():
    pages = sorted(DOCS.glob("*.html"))
    assert pages, "no docs pages found"
    broken = []
    for page in pages:
        for href in _internal_hrefs(page.read_text(encoding="utf-8")):
            target = href.split("#", 1)[0]  # drop any anchor fragment
            if target and not (DOCS / target).exists():
                broken.append(f"{page.name} -> {href}")
    assert not broken, f"broken internal links: {broken}"


def test_docs_pages_agree_on_one_repository_url():
    bases = set()
    for page in DOCS.glob("*.html"):
        for url in re.findall(r"https://github\.com/[^\"'\s)]+", page.read_text(encoding="utf-8")):
            match = re.match(r"(https://github\.com/[^/]+/[^/]+?)(\.git)?/?$", url.rstrip(".,"))
            if match:
                bases.add(match.group(1))
    assert len(bases) <= 1, f"docs pages disagree on the repository URL: {bases}"
