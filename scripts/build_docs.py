"""Generate the full user guide, docs/guide.html, for GitHub Pages.

One self-contained page: every command, the whole workflow, the questionnaire,
how to read the report and plan, privacy, and troubleshooting, in plain English.
It inlines iamai.theme.BASE_CSS so it is visibly the same product as the report,
the plan and the wizard. Regenerate after changing the theme or the content:

    python scripts/build_docs.py

tests/test_docs_page.py fails if docs/guide.html drifts from this script, and
also if a CLI command exists that the guide never mentions, so the guide cannot
silently fall behind the tool.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from iamai.theme import BASE_CSS  # noqa: E402
from build_demo import (  # noqa: E402  (single source for slug, theme, chrome)
    COPY_SCRIPT, DARK_CSS, REPO_URL, code_block, site_footer, site_header,
)

DOCS_CSS = """
  main { max-width: 60rem; }
  .lead { font-size: 1.15rem; color: var(--ink-2); max-width: 48ch; }
  .toc { background: var(--surface); border: 1px solid var(--hairline); border-radius: var(--radius);
    box-shadow: var(--shadow); padding: 1.1rem 1.4rem; margin: 1.25rem 0 2rem; }
  .toc h2 { margin-top: 0; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
  .toc ol { columns: 2; column-gap: 2rem; margin: 0.4rem 0 0; padding-left: 1.2rem; }
  .toc li { margin: 0.3rem 0; break-inside: avoid; }
  .cmd { border: 1px solid var(--hairline); border-radius: var(--radius); margin: 1rem 0; overflow: hidden; }
  .cmd > .sig { background: var(--code-bg); color: var(--code-ink); font-family: ui-monospace, Menlo, Consolas, monospace;
    padding: 0.7rem 1rem; font-size: 0.95rem; overflow-x: auto; }
  .cmd > .body { padding: 0.9rem 1.1rem; }
  .cmd > .body p { margin: 0 0 0.5rem; }
  .cmd .opts { width: 100%; margin-top: 0.5rem; }
  .cmd .opts td { vertical-align: top; padding: 0.3rem 0.6rem 0.3rem 0; }
  .cmd .opts td.flag { font-family: ui-monospace, Menlo, Consolas, monospace; white-space: nowrap; color: var(--brand); }
  pre.code { background: var(--code-bg); color: var(--code-ink); border-radius: var(--radius-sm);
    padding: 1rem 1.25rem; overflow-x: auto; font-size: 0.9rem; line-height: 1.5; }
  .grade-key td:first-child { font-weight: 700; white-space: nowrap; }
  dl.gloss dt { font-weight: 700; margin-top: 0.7rem; }
  dl.gloss dd { margin: 0.15rem 0 0; color: var(--ink-2); }
  @media (max-width: 40rem) { .toc ol { columns: 1; } }
"""

# --- Command reference, as data so the drift and coverage tests can check it ----
# (name, signature, description, [(flag, meaning), ...])
COMMANDS = [
    ("setup", "iamai setup",
     "Creates the read-only collector app in your tenant, generates the certificate it "
     "signs in with, and writes config.yaml. Run once per install. It prints a fast Azure "
     "CLI path and a manual portal path for the one-time helper-app registration, then walks "
     "you through consent.", []),
    ("consent", "iamai consent <alias>",
     "Prints the Microsoft admin-consent link for a tenant. Open it as a Global Administrator "
     "to grant the read permissions. Use it to add a second tenant after the first setup.", []),
    ("verify", "iamai verify <alias>",
     "Tests every permission with a real read and prints a pass/fail table. Run it after "
     "setup or consent to confirm the app can actually see what it needs before a full collect.", []),
    ("collect", "iamai collect <alias> [--days N]",
     "Reads the tenant over Microsoft Graph and writes a dated, read-only snapshot under "
     "data/<alias>/. Shows live progress as each dataset is pulled. Safe to run again; each "
     "run is a new snapshot.",
     [("--days N", "How many days of sign-in logs to pull. Default 30.")]),
    ("assess", "iamai assess <alias> [--pack PATH]",
     "Grades the latest snapshot against the standard and writes assessment.json plus an HTML "
     "report. Run it again after the questionnaire to fold your answers into the grades.",
     [("--pack PATH", "Grade against a specific standard pack (see packs/) instead of the built-in default.")]),
    ("wizard", "iamai wizard <alias> [--port N]",
     "Opens the questionnaire in your browser, on this machine only, then regrades "
     "automatically when you finish. This is what turns a generic report into one about your "
     "tenant. Answers are saved as you go, and you can move back and forward between questions.",
     [("--port N", "Local port for the wizard page. Default 8765.")]),
    ("questions", "iamai questions <alias>",
     "The same questionnaire as the wizard, answered in the terminal instead of a browser, "
     "then regrades automatically. Use it when you would rather not open a browser.", []),
    ("plan", "iamai plan <alias> [--start-date YYYY-MM-DD] [--pack PATH]",
     "Writes the remediation plan (plan.json plus an HTML plan) from the assessment and your "
     "answers. The plan is staged into phases, each ending at a checkpoint, and every step "
     "says what it costs users and how to undo it.",
     [("--start-date YYYY-MM-DD", "Day one of the rollout. Defaults to today in your report timezone."),
      ("--pack PATH", "The same standard you passed to assess, so every finding gets a step.")]),
    ("sanitize", "iamai sanitize <alias>",
     "Writes a pseudonymized copy of the latest snapshot: real names, sign-in names, IP "
     "addresses and the tenant id are replaced with stable stand-ins. This is the only copy "
     "safe to move off the machine or share.", []),
    ("purge", "iamai purge <alias> [--keep-latest N | --older-than N | --all] [--yes]",
     "Deletes collected data for a tenant. Every collect leaves real identity data on disk and "
     "nothing removes it on its own, so run this when an engagement ends or to prune old "
     "snapshots. It says exactly what it will delete before deleting, unless you pass --yes.",
     [("--keep-latest N", "Delete every snapshot except the most recent N."),
      ("--older-than N", "Delete snapshots older than N days."),
      ("--all", "Delete everything for this alias: snapshots, assessments, plans, answers, and the pseudonym map."),
      ("--yes, -y", "Delete without asking for confirmation.")]),
    ("baseline build", "iamai baseline build [--days N] [--yes]",
     "Advanced. Builds a standard from a well-run reference tenant instead of using a shipped "
     "pack: pulls the golden tenant, lets you curate the inventory, and freezes it as the "
     "active baseline. Most users never need this.",
     [("--days N", "How many days of sign-in logs to pull from the golden tenant. Default 30."),
      ("--yes, -y", "Accept the full inventory and default bindings without prompting.")]),
    ("baseline import", "iamai baseline import <pack_path>",
     "Advanced. Validates an authored standard pack (schema and static checks) and freezes it "
     "as the active baseline. No tenant needed.", []),
]

# --- Every read permission the collector requests, and what it reads -----------
PERMISSIONS = [
    ("Policy.Read.All", "Conditional Access policies, named locations, authentication methods and strengths, the authorization policy, security defaults, the admin consent workflow."),
    ("Directory.Read.All", "Users and groups."),
    ("RoleManagement.Read.Directory", "Directory role definitions and who holds them."),
    ("Application.Read.All", "Service principals (enterprise apps)."),
    ("AuditLog.Read.All", "Sign-in logs, and users' last sign-in activity."),
    ("Reports.Read.All", "Per-user authentication-method registration details."),
    ("Organization.Read.All", "The organization profile and its subscriptions and licenses."),
    ("Domain.Read.All", "Verified domains."),
    ("IdentityRiskyUser.Read.All", "Identity Protection risky users (needs Entra ID P2; skipped cleanly without it)."),
]

QUESTIONS = [
    ("Break-glass accounts", "Which accounts are your emergency sign-in accounts. The plan protects these first and keeps them out of new policies so you can never lock yourself out. Select none if you have none yet, and the plan will tell you to create one."),
    ("Trusted network locations", "Which networks are genuinely your company's. It lists the busiest sign-in addresses and flags a likely office or VPN, and you can type your office IP or range. Select none if your team is fully remote or you are unsure."),
    ("Unsanctioned exclusions", "For each account or group excluded from a policy in a way the standard does not expect, what it is (break-glass, service account, pilot group, onboarding group, or something else). This either approves the exclusion or flags it for cleanup."),
    ("Legacy authentication", "Which accounts still using old sign-in methods are service accounts run by software rather than people, so the plan can handle them before it blocks the old methods."),
    ("License tier", "Which Entra license the plan should assume, so it only proposes steps your license supports. The detected tier is shown to confirm."),
    ("Report timezone", "Which timezone reports and the plan should use for dates and times, chosen from a list."),
    ("Special handling", "Anyone who needs extra care during the rollout, such as executives, shared accounts, or people traveling. Optional."),
]

GRADES = [
    ("FULL", "Matches the standard."),
    ("FUNCTIONAL", "Protected, but built differently from the standard. Same security effect, different shape."),
    ("PARTIAL", "Present but weaker than the standard."),
    ("MISSING", "The protection does not exist in the tenant."),
    ("UNKNOWN", "The collected data could not judge it. Not a pass and not a fail, and never guessed."),
]

GLOSSARY = [
    ("Alias", "The short name you choose for a tenant. It appears in reports, so pick something you are happy to show."),
    ("Snapshot", "One read-only capture of a tenant from a single collect, stored under data/<alias>/<timestamp>/."),
    ("Break-glass account", "An emergency administrator account kept outside normal policies so someone can always get in."),
    ("Conditional Access policy", "A rule that decides whether a sign-in is allowed, and under what conditions (such as requiring multi-factor authentication)."),
    ("Named location", "A set of network addresses or countries a policy can treat specially, for example a trusted office network."),
    ("Baseline / pack", "The standard the tenant is graded against. A pack ships with the tool; a baseline can be built from a reference tenant."),
    ("Structural note", "An advisory observation about how the tenant is built. It never changes a grade."),
    ("Sanitize", "Replacing every real identifier in a snapshot with a stable stand-in, so a copy can be shared safely."),
]


def _esc(text: str) -> str:
    """Escape the command data, which is plain text: signatures carry <alias>
    and flags, which a browser would otherwise read as tags."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cmd_html(name, sig, desc, opts):
    rows = ""
    if opts:
        rows = '<table class="opts">' + "".join(
            f'<tr><td class="flag">{_esc(flag)}</td><td>{_esc(meaning)}</td></tr>' for flag, meaning in opts
        ) + "</table>"
    return (
        f'<div class="cmd"><div class="sig">{_esc(sig)}</div>'
        f'<div class="body"><p>{_esc(desc)}</p>{rows}</div></div>'
    )


def _section(anchor, title, inner, open=False):
    """A collapsible section. Closed by default so the long guide is scannable;
    a table-of-contents link opens the target via the shared hash handler."""
    attr = " open" if open else ""
    return (
        f'<details class="sect" id="{anchor}"{attr}><summary>{title}</summary>'
        f'<div class="sect-body">{inner}</div></details>'
    )


def _toc():
    items = [
        ("what", "What IAMAI is"), ("install", "Installing it"),
        ("setup", "Connecting a tenant"), ("workflow", "The workflow"),
        ("commands", "Command reference"), ("questionnaire", "The questionnaire"),
        ("report", "Reading the report"), ("plan", "Reading the plan"),
        ("sharing", "Sharing safely"), ("data", "Where your data lives"),
        ("permissions", "Permissions it uses"), ("skill", "Reading results with Claude"),
        ("trouble", "Troubleshooting"), ("resources", "Resources"), ("glossary", "Glossary"),
    ]
    lis = "".join(f'<li><a href="#{a}">{t}</a></li>' for a, t in items)
    return f'<nav class="toc"><h2>On this page</h2><ol>{lis}</ol></nav>'


def _build_sections():
    parts = []

    parts.append(_section("what", "What IAMAI is",
        "<p>IAMAI reads a Microsoft Entra tenant, grades its identity security against a clear "
        "standard, and writes a plan for closing the gaps in an order a real person can work "
        "through. It is built for the people who look after somebody else's tenant and have more "
        "tenants than hours.</p>"
        "<div class=\"callout\"><strong>It never changes anything.</strong> Every permission it "
        "asks for is a read permission. It cannot create, edit or delete a policy, an account or a "
        "setting. The plan it writes is a document a person carries out by hand. It sends nothing "
        "anywhere: the only traffic is to Microsoft's own Graph and login endpoints, and everything "
        "it collects stays in a folder on your machine.</div>", open=True))

    parts.append(_section("install", "Installing it",
        "<p>You need Windows, macOS or Linux and Python 3.12. You do not need to know Python. "
        "Run these four commands (each has a Copy button):</p>"
        + code_block("git clone " + REPO_URL + ".git iamai\ncd iamai\npython -m venv .venv\n"
          ".venv\\Scripts\\python.exe -m pip install --require-hashes -r requirements.txt\n"
          ".venv\\Scripts\\python.exe -m pip install --no-deps -e .")
        + "<p>On macOS or Linux the last two lines use <code>.venv/bin/python</code>. Installing from "
        "<code>requirements.txt</code> checks every dependency against a recorded hash, rather than "
        "trusting whatever a package index serves that day.</p>"))

    parts.append(_section("setup", "Connecting a tenant",
        "<p>Run <code>iamai setup</code>. It creates the read-only collector app, generates the "
        "certificate it uses, and walks you through granting consent.</p>"
        "<p><strong>A one-time helper app.</strong> Before the very first setup you register a small "
        "\"IAMAI Setup\" app in the tenant. This is deliberate: the alternative is a shared app "
        "controlled by whoever publishes this tool, which is its own trust problem. If you have the "
        "Azure CLI and are signed in as a Global Administrator, one command does it:</p>"
        + code_block('az ad app create --display-name "IAMAI Setup" '
          "--sign-in-audience AzureADMultipleOrgs --is-fallback-public-client true --query appId -o tsv")
        + "<p>Otherwise setup prints the handful of portal steps with a direct link. Then it prints an "
        "admin-consent link: open it as a Global Administrator and review the list. Every permission "
        "on it is a read permission.</p>"
        "<p><strong>The certificate.</strong> Setup generates a certificate valid for 180 days. It "
        "is the one credential the tool uses to read your tenants, so it is kept deliberately short "
        "lived. When it nears expiry the tool warns you; once expired it stops with a plain "
        "instruction to run setup again. To add another tenant later, send its administrator the "
        "link from <code>iamai consent &lt;alias&gt;</code>.</p>"))

    parts.append(_section("workflow", "The workflow",
        "<p>Five commands, in order. Each writes files and is safe to run again.</p>"
        + code_block("iamai verify  &lt;alias&gt;   # check every permission actually works\n"
          "iamai collect &lt;alias&gt;   # read the tenant into a dated snapshot\n"
          "iamai assess  &lt;alias&gt;   # grade it and write the report\n"
          "iamai wizard  &lt;alias&gt;   # answer the questions in your browser\n"
          "iamai plan    &lt;alias&gt;   # write the plan")
        + "<p>Run <code>assess</code> again after the wizard and the grades reflect what you told it. "
        "Everything lands under <code>data/&lt;alias&gt;/</code>. Reports and plans are HTML: open "
        "them in a browser, and print to PDF to keep or send a copy.</p>"))

    parts.append(_section("commands", "Command reference",
        "<p>Every command. <code>&lt;alias&gt;</code> is the short name you gave a tenant.</p>"
        + "".join(_cmd_html(*c) for c in COMMANDS)))

    parts.append(_section("questionnaire", "The questionnaire",
        "<p>The wizard (or <code>iamai questions</code>) asks only what the data cannot answer on "
        "its own. Each question shows what the data already found and why it is being asked. Your "
        "answers are saved as you go, and you can move back and forward to change them.</p>"
        "<dl class=\"gloss\">" + "".join(f"<dt>{_esc(t)}</dt><dd>{_esc(d)}</dd>" for t, d in QUESTIONS) + "</dl>"))

    parts.append(_section("report", "Reading the report",
        "<p>The report grades each control on two separate axes. <strong>Grade</strong> is the "
        "security effect. <strong>Structural</strong> is an advisory note about how the tenant is "
        "built, and it never changes a grade. There is no single score or percentage on purpose: a "
        "number invites a target and hides which specific protection is weak.</p>"
        "<p>A grade is never better than the evidence. If the data cannot judge something it is "
        "graded UNKNOWN, which is not a pass and not a fail.</p>"
        "<table class=\"grade-key\"><tr><th>Grade</th><th>Meaning</th></tr>"
        + "".join(f"<tr><td>{_esc(g)}</td><td>{_esc(m)}</td></tr>" for g, m in GRADES) + "</table>"
        f"<p>See a <a href=\"example-report.html\">sample report</a> rendered from sanitized data.</p>"))

    parts.append(_section("plan", "Reading the plan",
        "<p>The plan is the report turned into work. It is staged into <strong>phases</strong>, each "
        "ending at a <strong>checkpoint</strong> you confirm before moving on. Every <strong>step"
        "</strong> says what to change, what it will cost the people who use the tenant (stated up "
        "front), how to check it worked, and how to undo it. It also carries ready-to-send "
        "announcement and helpdesk templates. Nothing in the plan is performed by the tool: a person "
        "reads it, decides, and makes each change by hand.</p>"))

    parts.append(_section("sharing", "Sharing a report safely",
        "<p>The report, the plan and every raw dataset name real people and carry the real tenant "
        "id, because they are made on your machine for you to read there. To share any of it, run "
        "<code>iamai sanitize &lt;alias&gt;</code>, which writes a copy with every real name, "
        "sign-in name, IP address and tenant id replaced by a stable stand-in. Only that copy is "
        "safe to move off the machine.</p>"))

    parts.append(_section("data", "Where your data lives",
        "<p>Everything is under <code>data/&lt;alias&gt;/</code>, one folder per tenant.</p>"
        "<pre class=\"code\">data/&lt;alias&gt;/\n"
        "  &lt;timestamp&gt;/            one snapshot per collect\n"
        "    manifest.json        what was pulled, when, and whether it was complete\n"
        "    raw/                 the raw datasets, plus gzipped sign-in feeds\n"
        "  assessments/\n"
        "    &lt;timestamp&gt;-assessment.json   the graded result\n"
        "    &lt;timestamp&gt;-report.html       the report for it\n"
        "  plans/\n"
        "    &lt;timestamp&gt;-plan.json / .html the plan</pre>"
        "<p><strong>Deleting it.</strong> Nothing is removed on its own. Run "
        "<code>iamai purge &lt;alias&gt; --all</code> when an engagement ends, or "
        "<code>--keep-latest N</code> / <code>--older-than N</code> to prune old snapshots. It "
        "confirms before deleting unless you pass <code>--yes</code>.</p>"))

    parts.append(_section("permissions", "Permissions it uses, and why",
        "<p>Setup asks for one write permission, <code>Application.ReadWrite.OwnedBy</code>, used "
        "only to create the collector app itself. It cannot touch any other app. Everything the "
        "collector then reads uses read-only permissions:</p>"
        "<table><tr><th>Permission</th><th>What it reads</th></tr>"
        + "".join(f"<tr><td><code>{_esc(p)}</code></td><td>{_esc(w)}</td></tr>" for p, w in PERMISSIONS) + "</table>"))

    parts.append(_section("skill", "Reading results with Claude",
        "<p>The repository ships a Claude Code skill, <code>iamai-review</code>, at "
        "<code>.claude/skills/iamai-review/</code>. If you run Claude Code from inside the "
        "directory it loads automatically, and you can ask in plain language how the tenant stands, "
        "why a control got its grade, what the plan says to do first, or anything about the raw "
        "data. It reads the tool's own results and restates them faithfully; it never re-grades or "
        "changes the tenant, and it treats everything under <code>data/</code> as the real identity "
        "data it is.</p>"))

    parts.append(_section("trouble", "Troubleshooting",
        "<dl class=\"gloss\">"
        "<dt>verify shows a permission failing</dt><dd>Consent was not fully granted. Open the link "
        "from <code>iamai consent &lt;alias&gt;</code> again as a Global Administrator and accept the "
        "whole list, then re-run verify.</dd>"
        "<dt>The tool says the certificate expired</dt><dd>The certificate lasts 180 days by design. "
        "Run <code>iamai setup</code> again to generate a fresh one.</dd>"
        "<dt>collect finished but says PARTIAL</dt><dd>A dataset could not be fully read (often a "
        "license-gated one like risky users). The snapshot is kept and the assessment says so "
        "honestly; grades that needed the missing data become UNKNOWN rather than a guess.</dd>"
        "<dt>The wizard will not open</dt><dd>Something else may be using the port. Run "
        "<code>iamai wizard &lt;alias&gt; --port 8790</code> (any free port). The page is served on "
        "127.0.0.1 only and refuses any non-loopback address.</dd>"
        "<dt>Report times look wrong</dt><dd>Set your timezone in the wizard's timezone question, "
        "then run <code>iamai assess</code> and <code>iamai plan</code> again.</dd>"
        "</dl>"))

    parts.append(_section("resources", "Resources",
        "<p>All part of the repository:</p><ul>"
        "<li><a href=\"index.html\">Overview and download</a>, <a href=\"use-cases.html\">use cases</a>, and a <a href=\"example-report.html\">sample report</a>.</li>"
        "<li><code>README.md</code> &middot; the quick start and rules the tool runs under.</li>"
        "<li><code>ARTIFACTS.md</code> and <code>schemas/</code> &middot; the assessment and plan JSON contract, for anyone building on the output.</li>"
        "<li><code>ASSUMPTIONS.md</code> &middot; every Graph behaviour that was verified, with sources.</li>"
        "<li><code>SECURITY.md</code> &middot; the security model, data handling, and how to report an issue.</li>"
        "<li><code>CONTRIBUTING.md</code> &middot; how to set up, test, and the rules the project runs under.</li>"
        f"<li><a href=\"{REPO_URL}\">Source on GitHub</a>, open source under the Apache License 2.0.</li>"
        "</ul>"))

    parts.append(_section("glossary", "Glossary",
        "<dl class=\"gloss\">" + "".join(f"<dt>{_esc(t)}</dt><dd>{_esc(d)}</dd>" for t, d in GLOSSARY) + "</dl>"))

    return "".join(parts)


BODY = f"""<body>
{site_header("guide")}
<main id="top">
  <h1>IAMAI user guide</h1>
  <p class="lead">Everything the tool does, in plain English: install it, connect a tenant,
    run the assessment, and read what comes out. Each section below expands.</p>
  {_toc()}
  {_build_sections()}
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
<title>IAMAI user guide: every command and feature in plain English</title>
<meta name="description" content="The full IAMAI user guide: install, connect a Microsoft Entra tenant, run the assessment, read the report and plan, share safely, and a complete command reference. Read only, local, no telemetry.">
<style>{BASE_CSS}{DOCS_CSS}{DARK_CSS}</style>
</head>
"""


def render() -> str:
    return HEAD + BODY + "\n"


def main() -> None:
    out = ROOT / "docs" / "guide.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {out} ({len(render())} bytes)")


if __name__ == "__main__":
    main()
