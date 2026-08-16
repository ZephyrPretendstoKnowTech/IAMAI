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

from iamai.grade import assess_snapshot  # noqa: E402
from iamai.report import render_assessment  # noqa: E402
from iamai.store import load_snapshot_data  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "golden_sanitized"
PACK = ROOT / "src" / "iamai" / "packs" / "basics-v1.json"


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
    # This published sample is part of the docs site, so give it a way back.
    # Injected here only, never into a real report (which stays self-contained
    # with no outbound links). Internal doc links only; no external URL, because
    # a report must carry none.
    link = 'style="color:#6cb0ff;text-decoration:none;font-weight:600;"'
    banner = (
        '<div style="background:#0b1a30;color:#c4d1e2;padding:0.6rem 1.5rem;'
        'font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;text-align:center;">'
        'A sample IAMAI report, rendered from sanitized data. &nbsp;'
        f'<a href="index.html" {link}>Overview</a> &middot; '
        f'<a href="use-cases.html" {link}>Use cases</a> &middot; '
        f'<a href="guide.html" {link}>Guide</a>'
        '</div>'
    )
    return html.replace("<body>", "<body>\n" + banner, 1)


def main() -> None:
    out = ROOT / "docs" / "example-report.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {out} ({len(render())} bytes)")


if __name__ == "__main__":
    main()
