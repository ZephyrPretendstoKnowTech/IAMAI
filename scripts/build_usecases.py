"""Generate the use-cases page, docs/use-cases.html, for GitHub Pages.

A value-and-purpose page: who IAMAI is for and how it fits real work. It reuses
iamai.theme.BASE_CSS and the landing page's layer so it is visibly one product.
Everything here is illustrative and grounded in what the tool actually does:
no invented customers, quotes, logos or statistics. Regenerate after a theme or
copy change:

    python scripts/build_usecases.py

tests/test_demo_page.py fails if docs/use-cases.html drifts from this script.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from iamai.theme import BASE_CSS  # noqa: E402
from build_demo import REPO_URL, LANDING_CSS  # noqa: E402  (reuse hero/grid/feature)

EXTRA_CSS = """
  .scenario { border: 1px solid var(--hairline); border-radius: var(--radius);
    background: var(--surface); box-shadow: var(--shadow); padding: 1.25rem 1.4rem; margin: 1rem 0; }
  .scenario h3 { margin: 0 0 0.35rem; }
  .scenario .step { color: var(--brand); font-weight: 700; font-size: 0.85rem;
    text-transform: uppercase; letter-spacing: 0.04em; }
  .scenario code { font-size: 0.9rem; }
  .pillars { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: 1rem; margin: 1.25rem 0; }
  .pillar { border-left: 4px solid var(--brand); padding: 0.2rem 0 0.2rem 1rem; }
  .pillar h3 { margin: 0 0 0.25rem; font-size: 1.05rem; }
  .pillar p { margin: 0; color: var(--ink-2); font-size: 0.95rem; }
"""

PERSONAS = [
    ("The managed IT provider",
     "You look after many client tenants and have more of them than you have hours. You need "
     "each one assessed against the same standard, quickly, and a report and plan per client "
     "without hand-auditing every policy."),
    ("The internal admin",
     "You run one or a few tenants and wear every hat. You are not a Conditional Access "
     "specialist, and you want a plain-English answer to \"where do we stand, and what should I "
     "do next?\" that you can act on."),
    ("The security consultant",
     "You do identity posture reviews. You want a fast, repeatable, evidence-based assessment "
     "and a defensible remediation plan you can hand over, plus a clean copy you can share "
     "without exposing the client."),
    ("Whoever inherited the tenant",
     "You picked up a tenant with no history and no documentation. You need an honest map of "
     "what is actually configured before you touch anything."),
]

# (step-label, title, body-html)
SCENARIOS = [
    ("Onboarding", "Baseline a new client in minutes",
     "A new tenant lands on your plate. Run <code>collect</code> then <code>assess</code> and "
     "you have a graded report of where its identity security actually stands, against a clear "
     "standard, before your first call. No clicking through a dozen blades to piece it together."),
    ("Review", "See what changed since last time",
     "Every collect is a dated, immutable snapshot. Re-run it next quarter and the assessment "
     "reflects the tenant as it is now, so a recurring check-up is one command, not a fresh "
     "manual audit."),
    ("Remediation", "Turn findings into a rollout a person can run",
     "The plan is the report turned into staged work: each phase ends at a checkpoint you "
     "confirm, and every step says what it will cost the people who use the tenant, how to "
     "verify it worked, and how to undo it. It even carries announcement and helpdesk "
     "templates. The tool writes it; a person carries it out."),
    ("Reporting", "Hand over something the client can trust",
     "Run <code>sanitize</code> and every real name, sign-in name, IP and tenant id becomes a "
     "stable stand-in. The result shows exactly what the real report says, with nobody exposed, "
     "so it is safe to attach to an email or a ticket."),
    ("Triage", "Understand an unfamiliar tenant fast",
     "Inherited a tenant nobody documented? A single read-only pass gives you an honest picture "
     "of its policies, admins, sign-in methods and gaps, so you know what you are dealing with "
     "before you change a thing."),
]

PILLARS = [
    ("It cannot break anything",
     "Every permission is a read permission. It cannot create, edit or delete a policy, an "
     "account or a setting. Running it on a live production tenant is safe by construction."),
    ("Nothing leaves the machine",
     "No telemetry, no accounts, no uploads. The only traffic is to Microsoft's own endpoints, "
     "and everything it collects stays in a folder you control. Sharing is a deliberate, "
     "sanitized step you take on purpose."),
    ("It never overstates",
     "A grade is never better than the evidence. Where the data cannot judge something it says "
     "UNKNOWN rather than guessing, and there is no single vanity score to chase, so you always "
     "see which specific protection is weak."),
    ("It is free and open",
     "Open source under the Apache License 2.0. Read the standard it grades against, read the "
     "code, run it on your own machine, forever."),
]


def _persona_cards():
    return "".join(
        f'<div class="feature"><h3>{t}</h3><p>{b}</p></div>' for t, b in PERSONAS
    )


def _scenarios():
    return "".join(
        f'<div class="scenario"><div class="step">{step}</div><h3>{title}</h3><p>{body}</p></div>'
        for step, title, body in SCENARIOS
    )


def _pillars():
    return "".join(
        f'<div class="pillar"><h3>{t}</h3><p>{b}</p></div>' for t, b in PILLARS
    )


BODY = f"""<body>
<main>
  <div class="brandbar"><span class="mark">iA</span> IAMAI <span class="sub">&middot; use cases</span></div>

  <section class="hero">
    <h1>Know where a tenant stands, and what to do about it.</h1>
    <p class="lead">IAMAI is for the people responsible for an identity they did not set up:
    the providers, admins and consultants who need a straight answer about a Microsoft Entra
    tenant's security and a plan they can actually carry out.</p>
    <div class="cta-row">
      <a class="btn" href="{REPO_URL}">Get it on GitHub</a>
      <a class="btn ghost" href="example-report.html">See a sample report</a>
      <a class="btn ghost" href="guide.html">Read the guide</a>
    </div>
  </section>

  <h2>Who it is for</h2>
  <div class="grid">{_persona_cards()}</div>

  <h2>Where it fits</h2>
  {_scenarios()}

  <h2>Why this tool, and not a script or a spreadsheet</h2>
  <div class="pillars">{_pillars()}</div>

  <div class="never">
    <strong>The honest part.</strong>
    <ul>
      <li>It is an enablement tool, not a replacement for judgement. It will tell you nobody
      should hold Global Administrator around the clock. It does not know that the account
      holding it runs your payroll export. Every recommendation is a starting point to weigh
      against the tenant in front of you.</li>
      <li>It is not a compliance certification and it is not an audit. It reads what Microsoft
      Graph exposes and grades it against a clear, published standard, no more and no less.</li>
    </ul>
  </div>

  <h2>See for yourself</h2>
  <p>Read a <a href="example-report.html">sample report</a> rendered from sanitized data, follow
  the <a href="guide.html">full guide</a>, or <a href="{REPO_URL}">get it on GitHub</a> and run it
  against a tenant of your own. From install to a report in hand is about fifteen minutes.</p>

  <footer>
    IAMAI is open source under the Apache License 2.0. Read only, local, no telemetry.
    &middot; <a href="{REPO_URL}">Source on GitHub</a>
  </footer>
</main>
</body>
</html>"""

HEAD = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IAMAI use cases: who it is for and the value it delivers</title>
<meta name="description" content="Who IAMAI is for and how it fits real work: baseline a new client, review what changed, turn findings into a staged remediation plan, and hand over a sanitized report. Read only, local, open source.">
<style>{BASE_CSS}{LANDING_CSS}{EXTRA_CSS}</style>
</head>
"""


def render() -> str:
    return HEAD + BODY + "\n"


def main() -> None:
    out = ROOT / "docs" / "use-cases.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {out} ({len(render())} bytes)")


if __name__ == "__main__":
    main()
