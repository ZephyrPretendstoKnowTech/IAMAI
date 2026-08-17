# IAMAI

IAMAI reads a Microsoft Entra tenant and tells you, in plain language, how its
identity security actually stands. It then writes a plan for closing the gaps,
in an order a real person can work through.

It is built for the people who look after somebody else's tenant and have more
tenants than hours.

The full **[user guide](docs/guide.html)** covers every command and feature in
plain English (open `docs/guide.html`, or read it on the project's GitHub Pages
site). This README is the quick start.

## What it does

1. **Reads the tenant.** Conditional Access policies, sign in methods, roles,
   guest and consent settings, sign in logs. Nothing else.
2. **Grades what it found** against a standard that ships with the tool.
3. **Asks you the handful of questions the data cannot answer**, such as which
   accounts are the emergency accounts you must never lock out.
4. **Writes a report and a plan.** The report says where the tenant stands.
   The plan is a series of steps, each one saying what to change, what it will
   cost the people who use the tenant, how to check it worked, and how to undo
   it.

## What it will never do

**It never changes anything.** Every permission it asks for is a read
permission. It cannot create, edit or delete a policy, an account or a setting,
because it was never given the ability to. The plan it writes is a document.
Somebody has to read it, decide, and make the changes by hand.

That is deliberate and it is not going to change. A tool that silently
reconfigures identity is a tool that can lock a company out of its own systems
at three in the morning.

It also sends nothing anywhere. No telemetry, no analytics, no accounts, no
uploads. The only outbound traffic is to `graph.microsoft.com` and
`login.microsoftonline.com`, which are Microsoft's own endpoints and are what
you are asking it to read. Everything it collects stays in a folder on your
machine.

## What it is, and what it is not

This is an enablement tool. It is not a replacement for knowing what you are
doing.

It will tell you that nobody should hold Global Administrator around the clock.
It does not know that the account holding it runs your payroll export, or that
the person who set it up left in March, or that your client has a merger
closing on Friday. Every recommendation is a starting point to be judged
against the tenant in front of you.

It is not a compliance certification and it is not an audit. Where the report
maps findings to published guidance, it maps only the specific items it
checked, and it says so on the page.

The licence says all of this in legal terms: the software is provided without
warranty of any kind, and the risk of using it is yours. This section is the
same thing in the words that actually matter.

## Getting started

You need a Windows, macOS or Linux machine and Python 3.12. You do not need to
know Python.

**1. Install it.** One line, no Python knowledge needed. It finds or installs
Python, installs IAMAI into its own isolated place (nothing clutters your
folders), and starts the guided setup.

On **Windows**, in PowerShell:

```
irm https://raw.githubusercontent.com/ZephyrPretendstoKnowTech/IAMAI/master/scripts/install.ps1 | iex
```

On **macOS or Linux**, in a terminal:

```
curl -fsSL https://raw.githubusercontent.com/ZephyrPretendstoKnowTech/IAMAI/master/scripts/install.sh | bash
```

**The careful way (verifies every dependency against a recorded hash).** Clone
the repository and install from the locked `requirements.txt`:

```
git clone https://github.com/ZephyrPretendstoKnowTech/IAMAI.git iamai
cd iamai
python -m venv .venv
.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.txt
.venv\Scripts\python.exe -m pip install --no-deps -e .
```

On macOS or Linux the last two lines use `.venv/bin/python`. This path verifies
every dependency, direct and transitive, against a hash recorded when it was
locked, rather than whatever a package index happens to serve on the day of
install. Each release also records its wheel's SHA256 in the release notes.

**2. Confirm the install worked.**

```
iamai --version
iamai doctor
```

`--version` proves the command runs. `doctor` checks the whole install in one
go and, beside anything wrong, prints the exact next command to run. (The
one-line installer already ran the verification itself; this is how you re-run
it any time.)

**3. Connect it to a tenant.**

```
iamai setup
```

Four explained steps: a one-time sign-in app, a browser sign-in as a Global
Administrator of the tenant to assess (the tenant is read from your sign-in,
so there is no ID to find and paste), the read-only Collector app with every
permission listed before anything is created, and Microsoft's approval link.
It prints every step and tells you what it needs before it needs it. To remove
everything later, `iamai uninstall` prints the exact steps.

**What you are approving, in plain terms.** Setup does two things that need a
Global Administrator, and it is worth knowing exactly what each one is:

- **A one-time browser sign in** (device code) so setup can create the app.
  This sign in requests a single permission, `Application.ReadWrite.OwnedBy`,
  which lets it create and manage *only the app it is creating* and nothing
  else in your tenant. It deliberately does not request the broader
  "read-write everything" or "grant permissions" scopes, so setup can never
  rewrite another app or grant itself access.
- **One consent click.** Setup then prints a Microsoft admin-consent link.
  You open it, still signed in as an administrator, and review the list before
  accepting. Every permission on that list is a *read* permission. This is
  where the app actually gets its access, on Microsoft's own screen, not from
  the tool.

**A one-time prerequisite.** Before the very first `setup`, you register a small
"IAMAI Setup" helper app in the tenant. This is deliberate: the alternative would
be a shared helper app controlled by whoever publishes this tool, which is its
own trust problem. Setup detects when this has not been done and prints two ways
to do it. If you have the Azure CLI and are signed in as a Global Administrator,
one command does it:

```
az ad app create --display-name "IAMAI Setup" --sign-in-audience AzureADMultipleOrgs --is-fallback-public-client true --query appId -o tsv
```

That prints the client ID `setup` then asks for. Otherwise setup prints the
handful of portal clicks (New registration, multitenant, allow public client
flows, copy the client ID) with a direct link to the registration page, so you
can follow along.

To add another tenant afterwards, send its administrator the link printed by
`iamai consent <alias>`. An alias is just a short name you choose for that
tenant. It is what appears in the reports, so pick something you are willing to
see on a page you might hand to somebody.

**The certificate, and renewing it.** Setup generates a certificate valid for
180 days. It is the one credential the tool uses to read your tenants, so it is
kept deliberately short lived: when it nears expiry the tool warns you, and once
it has expired it stops with a plain instruction to run `setup` again rather
than a confusing error. If you look after several tenants under one install, be
aware that this single certificate is what authenticates to all of them, so
treat the `certs/` folder accordingly, and note that running `setup` on a second
machine replaces the certificate and will stop the first machine from
authenticating until it is re-run there too.

**4. Run it.**

```
iamai verify <alias>      Check every permission actually works
iamai collect <alias>     Read the tenant into a dated snapshot
iamai assess <alias>      Grade it and write the report
iamai wizard <alias>      Answer the questions in your browser
iamai plan <alias>        Write the plan
```

Run them in that order. Each one writes files and can be run again safely.

`iamai wizard` opens a page on your own machine only. Answering its questions
is what turns a generic report into one about your tenant, so it is worth the
five minutes. Run `iamai assess` again afterwards and the grades will reflect
what you told it.

Everything lands under `data/<alias>/`. The reports and plans are HTML. Open
them in a browser, and print to PDF if you need to keep or send a copy.

## The standard it grades against

By default it uses `packs/basics-v1.json`, a set of controls covering the
things that matter most in a small tenant: phishing resistant sign in, blocking
the oldest protocols, who can invite guests, who can approve applications, and
who holds administrator roles permanently.

Each control records why it exists and, where one exists, the published
guidance it corresponds to. Where this tool asks for less than a published
baseline does, it does not claim to meet it.

The standard is fixed and versioned on purpose: a grade means the same thing
in every tenant, this year and next, which is what makes results comparable
across clients and over time. Tailoring to one tenant happens in the plan,
never in the grade. (Advanced users can import an authored pack with
`iamai baseline import`; most people will not need to.)

## Licensing aware

If a control needs an Entra ID P1 or P2 licence the tenant does not have, it is
not counted against them and it is not reported as a failure. It is listed
separately, with what you can do without the licence, so buying it stays a
decision somebody makes on purpose rather than something they were never told
about.

## Sharing a report safely

Reports name real people, because a plan that cannot say which account to fix
is not much use.

If you need to share one outside your organisation, `iamai sanitize <alias>`
writes a copy of a snapshot with names, addresses and identifiers replaced by
stable stand ins. Only sanitized snapshots should ever leave the machine or be
committed anywhere.

## Deleting a tenant's data

Every `iamai collect` leaves a full copy of real names, sign-in history, and
until sanitized, IP and location data on disk. Nothing removes it on its own.

When an engagement ends, run `iamai purge <alias> --all` to delete everything
collected for that tenant: every snapshot, assessment, plan, the answers file,
and the pseudonym map. To prune older snapshots while keeping an alias in
active use, `iamai purge <alias> --keep-latest N` or `iamai purge <alias>
--older-than N` (days) removes only the old snapshots and leaves your answers
and reports in place. Both ask for confirmation and say exactly what will be
deleted before deleting it, unless run with `--yes`.

## Reading the results with Claude

The repository ships a Claude Code skill, `iamai-review`, at
`.claude/skills/iamai-review/`. If you run Claude Code from inside this
directory, it loads automatically, and you can ask questions in plain language:
how the tenant stands, why a control got the grade it did, what the plan says to
do first, or anything about the raw collected data (which accounts lack MFA,
which apps hold a credential, who signed in from where).

The skill reads the engine's own artifacts and restates them faithfully. It does
not re-grade, invent findings, or change the tenant, and it treats everything
under `data/` as the real, unsanitised identity data it is: it will not transmit
those files anywhere. To use it elsewhere, copy the folder into your global
`~/.claude/skills/`.

## For developers

```
.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.txt
.venv\Scripts\python.exe -m pip install --no-deps -e .
.venv\Scripts\python.exe -m pytest -q
```

The suite makes zero live network calls. Every Graph interaction is served from
recorded, sanitized fixtures, and the test harness fails rather than allowing a
real request.

`requirements.txt` and `requirements-dev.txt` are generated, not
hand-written. After changing a pinned version in `pyproject.toml`, regenerate
both with [pip-tools](https://pypi.org/project/pip-tools/):

```
pip install pip-tools
pip-compile --generate-hashes --output-file=requirements.txt pyproject.toml
pip-compile --generate-hashes --extra=test --output-file=requirements-dev.txt pyproject.toml
```

- `SPEC-PUBLIC.md` is the contract for this version.
- `ARTIFACTS.md` documents the assessment and plan JSON a downstream reader (or
  a Claude skill) consumes, with machine-readable schemas in `schemas/`.
- `ASSUMPTIONS.md` records every Graph behaviour that was verified, with
  sources, including the ones that turned out to contradict what was assumed.
- `BUGS.md` records defects found and what was done about them.
- `CLAUDE.md` is the standing rules the project is built under.
- `SECURITY.md` covers the security model, data handling, and reporting an issue.
- `CONTRIBUTING.md` covers setup, tests, and the rules the project runs under.

## Licence

Apache License 2.0. See `LICENSE`.
