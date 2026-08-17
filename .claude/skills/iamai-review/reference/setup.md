# Walking a person through setup

This is the path from nothing installed to a finished report. Walk it with
the person one step at a time: give them the next command, tell them what it
will ask, and wait for what happened before moving on. They run every
command themselves. Setup and consent sign in interactively as a Global
Administrator, and collect reads their live tenant, so none of it is yours
to run for them.

The collector is fully usable without this skill. You are a guide to it,
not a wrapper around it.

## 1. Install

One line, in a terminal:

- Windows (PowerShell):
  `irm https://raw.githubusercontent.com/ZephyrPretendstoKnowTech/IAMAI/master/scripts/install.ps1 | iex`
- macOS or Linux:
  `curl -fsSL https://raw.githubusercontent.com/ZephyrPretendstoKnowTech/IAMAI/master/scripts/install.sh | bash`

The script checks for Python 3.12, creates an isolated environment, and puts
`iamai` on the PATH. If `iamai` is not found afterwards, have them open a new
terminal first; the PATH change lands in new sessions.

## 2. One-time app registration: `iamai setup`

`iamai setup` creates the read-only "IAMAI Collector" app registration in
their tenant and writes the config. What it asks, in order:

1. The tenant ID (called the golden tenant ID; for a person assessing their
   own tenant, that is simply their tenant's Directory ID, found on the
   Entra admin center overview page), and an alias to refer to it by.
   Aliases matter: reports name tenants by alias only.
2. Optionally a second tenant and alias, which can also be added later.
3. If no helper app exists yet, it pauses and shows two ways to create the
   one-time "IAMAI Setup" helper: a single Azure CLI command, or about two
   minutes in the portal (register a multitenant app, allow public client
   flows, copy the client ID). The person pastes the client ID back in.
4. A device code sign in: they open the printed URL, enter the code, and
   sign in as a Global Administrator of that tenant.

Setup then creates the Collector app with its ten read-only permissions,
generates a certificate (the standing credential; it expires after 180 days
and setup is simply run again to renew), writes the config, and prints an
admin consent URL.

Common snags:

- "Insufficient privileges" during setup: the signed-in account is not a
  Global Administrator of that tenant.
- The device code page loops: they signed into a different tenant than the
  ID they entered.

## 3. Approve the permissions

The consent URL setup printed is Microsoft's own approval page. The person
opens it signed in as a Global Administrator and approves. Every permission
is read-only; the tool cannot change anything in the tenant. For each
additional tenant, `iamai consent <alias>` prints that tenant's URL.

## 4. Prove it works: `iamai verify <alias>`

Runs one real read per permission and prints a pass or fail table. All ten
should PASS. A FAIL usually means consent has not been granted in that
tenant yet, or was granted by someone without the role to do it.

## 5. Read the tenant: `iamai collect <alias>`

Pulls every dataset into an immutable snapshot on their machine. The sign-in
feed is the slow part; a busy tenant can take minutes. The summary table at
the end shows per-dataset status; "partial" rows are worth noting, because
anything graded from partial data will say so.

## 6. Grade it: `iamai assess <alias>`

Grades the snapshot and writes the assessment plus an HTML report. With no
baseline imported, it grades against the standard pack that ships with the
tool, which is the right default for someone assessing their own tenant.

## 7. Answer what only they know: `iamai wizard <alias>`

Opens a page on their own machine (never the network) with a handful of
questions the data cannot answer, such as which account is the emergency
one and whether a trust was decided on purpose. Answers are saved, the
assessment regrades automatically, and a question is never asked twice.
`iamai questions <alias>` is the same thing in the terminal.

## 8. The plan: `iamai plan <alias>`

Writes the staged remediation plan, HTML and JSON. It needs an assessment
and the questionnaire answers first. From here, the person reads the plan
and this skill's main job takes over: interpreting results, which SKILL.md
covers.

## Where things land

Everything lives under one per-user folder (SKILL.md, "Find the files").
Nothing is sent anywhere: the tool talks only to Microsoft's Graph and
login endpoints, and the report is a local file.
