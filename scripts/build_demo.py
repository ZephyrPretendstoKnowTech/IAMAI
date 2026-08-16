"""Generate the public demo page, docs/index.html, for GitHub Pages.

The page inlines the same iamai.theme.BASE_CSS every other page uses, plus a
small landing-specific layer (hero, feature grid), so the demo, the report,
the plan and the wizard are visibly one product. Regenerate after changing the
theme or the copy:

    python scripts/build_demo.py

A test (tests/test_demo_page.py) fails if docs/index.html drifts from what this
script produces, so the committed page always matches the current theme.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iamai.theme import BASE_CSS  # noqa: E402

LANDING_CSS = """
  main { max-width: 60rem; }
  .hero { padding: 1.5rem 0 0.5rem; }
  .hero h1 { font-size: 2.2rem; max-width: 22ch; }
  .hero p.lead { font-size: 1.2rem; color: var(--ink-2); max-width: 46ch; margin: 0.75rem 0 1.5rem; }
  .cta-row { display: flex; gap: 0.75rem; flex-wrap: wrap; margin: 1.25rem 0; }
  .grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr));
    gap: 1rem; margin: 1.25rem 0;
  }
  .feature {
    background: var(--surface); border: 1px solid var(--hairline);
    border-radius: var(--radius); box-shadow: var(--shadow); padding: 1.25rem 1.4rem;
  }
  .feature .n {
    display: inline-flex; align-items: center; justify-content: center;
    width: 1.6rem; height: 1.6rem; border-radius: 6px;
    background: var(--brand-tint); color: var(--brand); font-weight: 800; font-size: 0.9rem;
    margin-bottom: 0.5rem;
  }
  .feature h3 { margin-bottom: 0.3rem; }
  .feature p { color: var(--ink-2); font-size: 0.95rem; margin: 0; }
  .never { background: var(--brand-tint); border-radius: var(--radius); padding: 1.4rem 1.6rem; margin: 1.5rem 0; }
  .never ul { margin: 0.5rem 0 0 1.1rem; }
  .never li { margin: 0.35rem 0; }
  pre.code {
    background: var(--ink); color: #eef3ee; border-radius: var(--radius-sm);
    padding: 1rem 1.25rem; overflow-x: auto; font-size: 0.9rem; line-height: 1.5;
  }
"""

# GitHub repository slug; the maintainer sets this to the real one before the
# repository goes public. Left generic so no unpublished name is baked in.
REPO_URL = "https://github.com/ZephyrPretendstoKnowTech/IAMAI"

BODY = f"""<body>
<main>
  <div class="brandbar"><span class="mark">iA</span> IAMAI</div>

  <section class="hero">
    <h1>See how a Microsoft Entra tenant's identity security actually stands.</h1>
    <p class="lead">IAMAI reads a tenant, grades it against a clear standard, and
    writes a plan for closing the gaps, in an order a real person can work
    through. Built for the people who look after somebody else's tenant and
    have more tenants than hours.</p>
    <div class="cta-row">
      <a class="btn" href="{REPO_URL}">Get it on GitHub</a>
      <a class="btn ghost" href="use-cases.html">Use cases</a>
      <a class="btn ghost" href="guide.html">Read the guide</a>
      <a class="btn ghost" href="example-report.html">See a sample report</a>
    </div>
    <p class="query">The sample is a real assessment rendered from sanitized
    data: every name in it is a stand in, so it shows exactly what your own
    report looks like without exposing anyone.</p>
  </section>

  <div class="never">
    <strong>It never changes anything.</strong>
    <ul>
      <li>Every permission it asks for is a read permission. It cannot create,
      edit or delete a policy, an account or a setting.</li>
      <li>The plan it writes is a document. A person reads it, decides, and makes
      the changes by hand.</li>
      <li>It sends nothing anywhere: no telemetry, no accounts, no uploads. The
      only traffic is to Microsoft's own Graph and login endpoints, and
      everything it collects stays in a folder on your machine.</li>
    </ul>
  </div>

  <h2 id="how">What it does</h2>
  <div class="grid">
    <div class="feature"><div class="n">1</div><h3>Reads the tenant</h3>
      <p>Conditional Access, sign in methods, roles, guest and consent settings,
      sign in logs. Read only, over Microsoft Graph.</p></div>
    <div class="feature"><div class="n">2</div><h3>Grades it</h3>
      <p>Against a standard that ships with the tool. Ambiguity grades down,
      never up, so a grade is never better than the evidence.</p></div>
    <div class="feature"><div class="n">3</div><h3>Asks what data can't answer</h3>
      <p>A short questionnaire for the handful of things only you know, such as
      which accounts are the emergency accounts you must never lock out.</p></div>
    <div class="feature"><div class="n">4</div><h3>Writes a report and a plan</h3>
      <p>The report says where the tenant stands. The plan is steps: what to
      change, what it costs the people who use the tenant, how to check it
      worked, and how to undo it.</p></div>
  </div>

  <h2>What it is, and what it is not</h2>
  <p>An enablement tool, not a replacement for knowing what you are doing. It will
  tell you that nobody should hold Global Administrator around the clock. It does
  not know that the account holding it runs your payroll export. Every
  recommendation is a starting point to be judged against the tenant in front of
  you. It is not a compliance certification and it is not an audit.</p>

  <h2>Getting it</h2>
  <p>You need a Windows, macOS or Linux machine and Python 3.12. You do not need
  to know Python. Clone the repository and follow the README:</p>
  <pre class="code">git clone {REPO_URL}.git iamai
cd iamai
python -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python -m pip install --no-deps -e .</pre>
  <p>Then <code>iamai setup</code> walks you through connecting a tenant, and
  <code>iamai collect</code>, <code>assess</code>, <code>wizard</code> and
  <code>plan</code> produce the report and plan. Every dependency is verified
  against a recorded hash at install time.</p>

  <footer>
    IAMAI is open source under the Apache License 2.0.
    Read only, local, no telemetry. &middot; <a href="{REPO_URL}">Source on GitHub</a>
  </footer>
</main>
</body>
</html>"""

HEAD = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IAMAI: read a Microsoft Entra tenant's identity security posture</title>
<meta name="description" content="IAMAI reads a Microsoft Entra tenant, grades its identity security against a clear standard, and writes a remediation plan. Read only, local, no telemetry. Open source, Apache 2.0.">
<style>{BASE_CSS}{LANDING_CSS}</style>
</head>
"""


def render() -> str:
    return HEAD + BODY + "\n"


def main() -> None:
    out = ROOT / "docs" / "index.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {out} ({len(render())} bytes)")


if __name__ == "__main__":
    main()
