"""Generate the sanitized example report the demo page links to.

docs/example-report.html is a real assessment, rendered from the committed
sanitized fixture (tests/fixtures/golden_sanitized), against the shipped pack.
It is safe to publish because the fixture is already sanitized: every name in
it is a pseudonym (User 1, user2@tenant.example, documentation IP ranges), so
the page shows exactly what an operator's own report looks like without
exposing anyone. Regenerate after a theme or pack change:

    python scripts/build_example_report.py

A test (tests/test_demo_page.py) fails if it drifts or if a real identifier
ever appears in it.
"""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from build_demo import DARK_CSS, site_header  # noqa: E402
from iamai.grade import assess_snapshot  # noqa: E402
from iamai.report import render_assessment  # noqa: E402
from iamai.store import load_snapshot_data  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "golden_sanitized"
PACK = ROOT / "src" / "iamai" / "packs" / "basics-v1.json"

# The published sample is one of the docs pages, so it wears the same dark theme
# and the same site header as the rest of the site. This is injected only here;
# a real generated report gets none of it and stays light and print-friendly.
# Layering DARK_CSS re-colours the report through the shared design tokens.
_SAMPLE_EXTRA_CSS = (
    "\n  .brandbar { display: none; }"  # the site header already brands the page
    "\n  .sample-note { background: var(--surface); border: 1px solid var(--hairline);"
    " border-radius: var(--radius); padding: 0.75rem 1.1rem; margin: 1.25rem 0;"
    " color: var(--ink-2); font-size: 0.92rem; }"
    "\n  .sample-note a { color: var(--brand); }"
)
_SAMPLE_NOTE = (
    '<div class="sample-note">A sample report, rendered from sanitized data, so every '
    'name in it is a stand in. It shows exactly what the tool produces, in the site theme. '
    '<a href="index.html">Back to the site</a>.</div>'
)


def render() -> str:
    pack = json.loads(PACK.read_text(encoding="utf-8"))
    data, manifest = load_snapshot_data(FIXTURE)
    assessment = assess_snapshot(
        pack, data, manifest,
        tenant_id="example-tenant", alias="Example Corp", snapshot_dir=FIXTURE,
    )
    # generatedAt/collectedAt would make the output change every run; blank them
    # so the committed page is stable and the drift test is meaningful.
    assessment["generatedAt"] = ""
    if manifest:
        manifest = {**manifest, "collectedAt": ""}
    html = render_assessment(assessment, manifest)
    # Dress the light report in the site's dark theme and header, so it reads as
    # one of the docs pages. All three edits touch this published copy only.
    html = html.replace(
        "</head>", f"<style>{DARK_CSS}{_SAMPLE_EXTRA_CSS}</style>\n</head>", 1
    )
    html = html.replace("<body>", "<body>\n" + site_header("sample"), 1)
    html = html.replace("<main>", "<main>\n" + _SAMPLE_NOTE, 1)
    return html


def main() -> None:
    out = ROOT / "docs" / "example-report.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {out} ({len(render())} bytes)")


if __name__ == "__main__":
    main()
