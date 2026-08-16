"""Generate the public demo page, docs/index.html, for GitHub Pages.

This module is also the shared foundation for the other docs pages
(scripts/build_docs.py, scripts/build_usecases.py): it exports the repo slug,
the dark theme override, and the site header/footer so every published page
carries the same navigation and credit. Regenerate after a change:

    python scripts/build_demo.py

A test (tests/test_demo_page.py) fails if docs/index.html drifts from what this
script produces, so the committed page always matches the current theme.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iamai.theme import BASE_CSS  # noqa: E402

# GitHub repository slug and the author's public credit. Shared by every page.
REPO_URL = "https://github.com/ZephyrPretendstoKnowTech/IAMAI"
AUTHOR = "Lachlan Robinette"
LINKEDIN = "https://www.linkedin.com/in/lachlanrobinette/"
# Inline (self-contained) LinkedIn glyph. No external asset.
LINKEDIN_SVG = (
    '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
    '<path d="M20.45 20.45h-3.55v-5.57c0-1.33-.02-3.04-1.85-3.04-1.85 0-2.14 1.45-2.14 '
    '2.94v5.67H9.35V9h3.41v1.56h.05c.47-.9 1.63-1.85 3.36-1.85 3.6 0 4.27 2.37 4.27 '
    '5.45v6.29zM5.34 7.43a2.06 2.06 0 1 1 0-4.13 2.06 2.06 0 0 1 0 4.13zM7.12 20.45H3.56V9h3.56z'
    'M22.22 0H1.77C.79 0 0 .77 0 1.72v20.56C0 23.23.79 24 1.77 24h20.45c.98 0 1.78-.77 '
    '1.78-1.72V1.72C24 .77 23.2 0 22.22 0z"/></svg>'
)

# Landing/use-cases layout layer (hero, feature grid). Light-theme neutral; the
# dark override below re-colours it through the shared tokens.
LANDING_CSS = """
  main { max-width: 60rem; }
  .hero { padding: 2rem 0 0.5rem; }
  .hero h1 { font-size: 2.4rem; line-height: 1.12; max-width: 20ch; }
  .hero p.lead { font-size: 1.2rem; color: var(--ink-2); max-width: 46ch; margin: 0.9rem 0 1.5rem; }
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
    width: 1.7rem; height: 1.7rem; border-radius: 7px;
    background: var(--brand-tint); color: var(--brand); font-weight: 800; font-size: 0.9rem;
    margin-bottom: 0.5rem;
  }
  .feature h3 { margin-bottom: 0.3rem; }
  .feature p { color: var(--ink-2); font-size: 0.95rem; margin: 0; }
  .never { background: var(--brand-tint); border: 1px solid var(--hairline); border-radius: var(--radius); padding: 1.4rem 1.6rem; margin: 1.5rem 0; }
  .never ul { margin: 0.5rem 0 0 1.1rem; }
  .never li { margin: 0.35rem 0; }
  pre.code {
    background: var(--code-bg); color: var(--code-ink); border: 1px solid var(--hairline);
    border-radius: var(--radius-sm); padding: 1rem 1.25rem; overflow-x: auto;
    font-size: 0.9rem; line-height: 1.55;
  }
"""

# Dark-blue theme. Layered last on the docs pages so it overrides the light
# tokens from BASE_CSS. Components refer only to tokens, so re-defining them
# reskins the whole page; the few extras below cover the header, the credit
# byline, the code blocks, and collapsible sections.
DARK_CSS = """
  :root {
    color-scheme: dark;
    --page: #0b1a30;
    --surface: #12273f;
    --surface-2: #0f2138;
    --ink: #eef3fb;
    --ink-2: #c4d1e2;
    --muted: #9fb0c6;
    --hairline: rgba(148, 176, 214, 0.18);
    --rule: rgba(148, 176, 214, 0.22);
    --brand: #6cb0ff;
    --brand-ink: #06152a;
    --brand-tint: #14314f;
    --accent-bar: #4f93f0;
    --ok: #56d364; --ok-tint: #10301c;
    --info: #56d4ca; --info-tint: #0f2f2d;
    --warn: #e3b341; --warn-tint: #2c2412;
    --bad: #ff6b64; --bad-tint: #331a19;
    --neutral: #9fb0c6; --neutral-tint: #1a2942;
    --code-bg: #061223; --code-ink: #d7e3f5;
    --shadow: 0 1px 2px rgba(0,0,0,0.35), 0 10px 30px rgba(0,0,0,0.28);
  }
  body {
    background:
      radial-gradient(1100px 480px at 82% -8%, rgba(108,176,255,0.12), transparent 62%),
      radial-gradient(900px 420px at 0% 0%, rgba(86,212,202,0.06), transparent 60%),
      var(--page);
    background-attachment: fixed;
  }
  .accent-strip { height: 3px; background: linear-gradient(90deg, #6cb0ff, #4f93f0, #56d4ca); }

  .site-header { position: sticky; top: 0; z-index: 10; border-bottom: 1px solid var(--hairline);
    background: rgba(9, 20, 38, 0.82); backdrop-filter: saturate(160%) blur(8px); }
  .site-header-inner { max-width: 60rem; margin: 0 auto; padding: 0.65rem 1.5rem;
    display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
  .wordmark { display: inline-flex; align-items: center; gap: 0.5rem; font-weight: 800;
    letter-spacing: -0.01em; color: var(--ink); text-decoration: none; font-size: 1.05rem; }
  .wordmark .mark { display: inline-flex; align-items: center; justify-content: center;
    width: 1.7rem; height: 1.7rem; border-radius: 7px; background: var(--brand); color: var(--brand-ink);
    font-weight: 800; font-size: 0.85rem; }
  .byline { display: flex; align-items: center; gap: 0.55rem; font-size: 0.85rem; color: var(--muted); }
  .byline strong { color: var(--ink-2); font-weight: 650; }
  .byline a.li { display: inline-flex; align-items: center; gap: 0.35rem; color: var(--brand);
    text-decoration: none; padding: 0.22rem 0.6rem; border: 1px solid var(--hairline); border-radius: 999px; }
  .byline a.li:hover { border-color: var(--brand); background: var(--brand-tint); }
  .byline svg { width: 14px; height: 14px; fill: currentColor; }
  .site-nav { border-top: 1px solid var(--hairline); background: rgba(7, 16, 31, 0.55); }
  .site-nav-inner { max-width: 60rem; margin: 0 auto; padding: 0.35rem 1.25rem; display: flex;
    gap: 0.35rem; flex-wrap: wrap; }
  .site-nav a { color: var(--ink-2); text-decoration: none; font-size: 0.9rem; font-weight: 550;
    padding: 0.4rem 0.7rem; border-radius: var(--radius-sm); }
  .site-nav a:hover { color: var(--ink); background: var(--brand-tint); }
  .site-nav a[aria-current="page"] { color: var(--brand); background: var(--brand-tint); }

  main { padding-top: 1.75rem; }
  a { color: var(--brand); }
  .brandbar { color: var(--muted); }

  /* Collapsible section (used in the guide). Open by default so the table of
     contents still jumps to visible content with no script, and print shows all. */
  details.sect { border: 1px solid var(--hairline); border-radius: var(--radius);
    background: var(--surface); box-shadow: var(--shadow); margin: 1rem 0; }
  details.sect > summary { cursor: pointer; list-style: none; padding: 0.95rem 1.25rem;
    font-size: 1.15rem; font-weight: 650; letter-spacing: -0.005em; color: var(--ink);
    display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
  details.sect > summary::-webkit-details-marker { display: none; }
  details.sect > summary::after { content: "\\25be"; color: var(--muted); font-size: 0.9rem;
    transition: transform 0.15s ease; }
  details.sect[open] > summary::after { transform: rotate(180deg); }
  details.sect[open] > summary { border-bottom: 1px solid var(--hairline); }
  details.sect .sect-body { padding: 0.4rem 1.25rem 1.25rem; }
  details.sect .sect-body > *:first-child { margin-top: 0.6rem; }
  .toplink { color: var(--muted); font-weight: 400; font-size: 0.8rem; }

  footer { color: var(--muted); border-top: 1px solid var(--hairline); }
  footer a { color: var(--brand); }

  /* Command block with a copy button (docs pages only). */
  .codeblock { position: relative; }
  .codeblock pre.code { margin: 0.6rem 0; }
  .codeblock .copy { position: absolute; top: 0.5rem; right: 0.5rem; margin: 0;
    padding: 0.3rem 0.7rem; font-size: 0.78rem; font-weight: 600; cursor: pointer;
    color: var(--ink-2); background: rgba(148,176,214,0.12); border: 1px solid var(--hairline);
    border-radius: var(--radius-sm); }
  .codeblock .copy:hover { color: var(--ink); border-color: var(--brand); }
  .codeblock .copy.done { color: var(--brand); border-color: var(--brand); }

  @media print {
    .codeblock .copy { display: none; }
    details.sect > .sect-body { display: block !important; }
    details.sect > summary::after { display: none; }
    .site-header, .accent-strip { position: static; }
  }
  @media (max-width: 40rem) {
    .site-header-inner { padding: 0.6rem 1rem; }
    .hero h1 { font-size: 1.9rem; }
  }
"""


def site_header(active: str) -> str:
    """The shared top bar: wordmark and credit on top, cross-page nav below.
    ``active`` marks the current page in the nav."""
    def link(href, label, key):
        current = ' aria-current="page"' if key == active else ""
        return f'<a href="{href}"{current}>{label}</a>'

    nav = "".join([
        link("index.html", "Overview", "overview"),
        link("use-cases.html", "Use cases", "usecases"),
        link("guide.html", "Guide", "guide"),
        link("example-report.html", "Sample report", "sample"),
        f'<a href="{REPO_URL}">GitHub</a>',
    ])
    return (
        '<div class="accent-strip"></div>'
        '<header class="site-header">'
        '<div class="site-header-inner">'
        '<a class="wordmark" href="index.html"><span class="mark">iA</span> IAMAI</a>'
        f'<div class="byline">Built by <strong>{AUTHOR}</strong>'
        f'<a class="li" href="{LINKEDIN}" aria-label="{AUTHOR} on LinkedIn">{LINKEDIN_SVG}'
        '<span>LinkedIn</span></a></div>'
        '</div>'
        f'<nav class="site-nav" aria-label="Site"><div class="site-nav-inner">{nav}</div></nav>'
        '</header>'
    )


def site_footer() -> str:
    return (
        '<footer>'
        'IAMAI is open source under the Apache License 2.0. Read only, local, no telemetry.<br>'
        f'Built by <strong>{AUTHOR}</strong> &middot; '
        f'<a href="{LINKEDIN}">LinkedIn</a> &middot; '
        f'<a href="{REPO_URL}">Source on GitHub</a>'
        '</footer>'
    )


def code_block(text: str) -> str:
    """A command block with a Copy button. `text` must already be HTML-safe."""
    return (
        '<div class="codeblock"><button class="copy" type="button" '
        'aria-label="Copy to clipboard">Copy</button>'
        f'<pre class="code">{text}</pre></div>'
    )


# One small inline script (docs pages only): wire every Copy button to the
# clipboard. Self-contained, makes no network request. The report, plan and
# wizard never include this.
COPY_SCRIPT = """<script>
document.querySelectorAll('.codeblock').forEach(function (block) {
  var button = block.querySelector('.copy');
  var pre = block.querySelector('pre');
  if (!button || !pre) return;
  button.addEventListener('click', function () {
    navigator.clipboard.writeText(pre.innerText).then(function () {
      button.textContent = 'Copied';
      button.classList.add('done');
      setTimeout(function () { button.textContent = 'Copy'; button.classList.remove('done'); }, 1500);
    });
  });
});
// Open a collapsed section when its anchor is the navigation target, so a
// table-of-contents link jumps straight to visible content with no extra click.
function openFromHash() {
  if (!location.hash) return;
  var target = document.querySelector(location.hash);
  if (target && target.tagName === 'DETAILS') { target.open = true; target.scrollIntoView(); }
}
window.addEventListener('hashchange', openFromHash);
openFromHash();
</script>"""


BODY = f"""<body>
{site_header("overview")}
<main>
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
  {code_block("git clone " + REPO_URL + ".git iamai\ncd iamai\npython -m venv .venv\n.venv/bin/python -m pip install --require-hashes -r requirements.txt\n.venv/bin/python -m pip install --no-deps -e .")}
  <p>Then <code>iamai setup</code> walks you through connecting a tenant, and
  <code>iamai collect</code>, <code>assess</code>, <code>wizard</code> and
  <code>plan</code> produce the report and plan. Every dependency is verified
  against a recorded hash at install time.</p>

  {site_footer()}
</main>
{COPY_SCRIPT}
</body>
</html>"""

HEAD = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IAMAI: read a Microsoft Entra tenant's identity security posture</title>
<meta name="description" content="IAMAI reads a Microsoft Entra tenant, grades its identity security against a clear standard, and writes a remediation plan. Read only, local, no telemetry. Open source, Apache 2.0.">
<style>{BASE_CSS}{LANDING_CSS}{DARK_CSS}</style>
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
