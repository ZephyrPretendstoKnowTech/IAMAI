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

from build_demo import REPO_URL  # noqa: E402
from iamai.grade import assess_snapshot  # noqa: E402
from iamai.report import render_assessment  # noqa: E402
from iamai.store import load_snapshot_data  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "golden_sanitized"
PACK = ROOT / "src" / "iamai" / "packs" / "basics-v1.json"

# A sticky dark header, matching the site, injected only into the published
# sample so it is navigable and consistent with the docs. Scoped .sample-*
# classes and explicit colours, so nothing here reaches the light report below.
# This is a docs page, so its nav may link out; a real generated report never
# does (render_assessment adds no links, and a test guards that).
SAMPLE_HEADER = f"""<style>
.sample-topbar {{ position: sticky; top: 0; z-index: 20; background: #0a1526;
  border-bottom: 1px solid rgba(148,176,214,0.18); }}
.sample-topbar .inner {{ max-width: 56rem; margin: 0 auto; padding: 0.6rem 1.5rem;
  display: flex; align-items: center; justify-content: space-between; gap: 0.75rem;
  flex-wrap: wrap; font: 14px system-ui, -apple-system, "Segoe UI", sans-serif; }}
.sample-topbar .wm {{ color: #eef3fb; font-weight: 800; text-decoration: none; font-size: 1.05rem; }}
.sample-topbar nav a {{ color: #c4d1e2; text-decoration: none; margin-left: 1.1rem; font-weight: 550; }}
.sample-topbar nav a:hover {{ color: #6cb0ff; }}
.sample-note {{ background: #12273f; color: #c4d1e2; text-align: center;
  padding: 0.5rem 1rem; font: 13px system-ui, -apple-system, "Segoe UI", sans-serif; }}
.sample-note a {{ color: #6cb0ff; }}
@media print {{ .sample-topbar, .sample-note {{ display: none; }} }}
</style>
<div class="sample-topbar"><div class="inner">
  <a class="wm" href="index.html">IAMAI</a>
  <nav>
    <a href="index.html">Overview</a>
    <a href="use-cases.html">Use cases</a>
    <a href="guide.html">Guide</a>
    <a href="{REPO_URL}">GitHub</a>
  </nav>
</div></div>
<div class="sample-note">A sample report, rendered from sanitized data, so every
name is a stand in. This is exactly what your own report looks like. <a href="index.html">Back to the site</a>.</div>"""


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
    # This published sample is part of the docs site, so give it the site's
    # header for navigation. Injected here only, never into a real report.
    return html.replace("<body>", "<body>\n" + SAMPLE_HEADER, 1)


def main() -> None:
    out = ROOT / "docs" / "example-report.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {out} ({len(render())} bytes)")


if __name__ == "__main__":
    main()
