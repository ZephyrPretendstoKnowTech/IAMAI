---
name: iamai-review
description: "Read and explain what IAMAI collected and graded for a Microsoft Entra tenant. Use whenever the user asks about a tenant's identity security posture, a specific control grade, the remediation plan, or the raw collected data (conditional access, users, roles, sign-ins, groups, service principals), or points at an IAMAI snapshot, assessment, or plan under data/. Reads the engine's own artifacts and restates them faithfully; investigates the raw snapshot for questions the grades do not answer. Read only: it never re-grades and never changes the tenant."
---

# iamai-review

IAMAI reads a Microsoft Entra tenant and produces three things on the operator's
machine: a **snapshot** (the raw Graph data it pulled), an **assessment** (each
control graded against a standard), and a **plan** (staged remediation). This
skill helps a person read all three and answer questions about the tenant,
without misreading the grades or leaking the data.

There are two jobs, and they have different rules:

- **Interpret the graded artifacts** (`assessment.json`, `plan.json`). Here you
  are a faithful reader of the engine's conclusions. You report its numbers and
  restate its words. You never re-grade.
- **Investigate the raw snapshot** (`raw/*.json`). Here you may analyse freely,
  because it is the underlying data. But an observation you make from raw data
  is your observation, not a grade, and must never be presented as one.

## Before anything else: two hard rules

**1. These files name real people and are not sanitised.** The assessment, the
plan, and every raw dataset carry real user principal names, display names, IP
addresses, and the real tenant id. Treat them as confidential identity data:

- Do not transmit them, paste them into a web tool, publish them, or copy their
  verbatim contents anywhere that leaves this machine.
- Quote only what the user's question needs. Prefer the `alias` over the tenant
  id, and counts or samples over full dumps.
- If the user wants to share any of this, the safe path is `iamai sanitize`,
  which pseudonymises a copy. Only that copy may leave the machine.

**2. The engine is the only source of truth for grading.** When you speak about
grades, you are quoting `assessment.json`, never deciding for yourself:

- Report the grade the engine computed. Never re-grade, override, or compute a
  new one, even if the raw data looks like it says otherwise. If they disagree,
  surface the disagreement; do not resolve it by overruling the engine.
- Never invent a control, a finding, or a fix. If a field is empty, the honest
  answer is that there is nothing there.
- Restate, do not reinterpret. `intent`, `rationale`, and plan step text are
  written to be read as-is. Paraphrasing can turn a careful statement wrong.
- Respect the two axes. `grade` is the security effect. `structural` is a
  separate advisory axis that **never** changes a grade. Never present a
  structural note as a failure.
- Respect conservatism. `UNKNOWN` means the data could not judge it. It is not a
  pass and not a fail; never show it as either.
- There is no score and no percentage, on purpose. Do not compute one. Report
  the per-grade counts and which specific protections are weak.

The full field-by-field contract is in `ARTIFACTS.md` at the repository root, and
the machine schemas are in `schemas/`. Read `ARTIFACTS.md` before explaining any
artifact field you are unsure of; this skill does not repeat it.

## Find the files

Everything lives under `data/<alias>/`. One tenant is one `alias`. Layout:

```
data/<alias>/
  <timestamp>/                 one snapshot per `iamai collect`
    manifest.json              what was pulled, when, and whether it is complete
    raw/                       the raw Graph datasets (see reference/datasets.md)
  assessments/
    <timestamp>-assessment.json   the graded result
    <timestamp>-report.html       the human report for that assessment
  plans/
    <timestamp>-plan.json         the staged remediation plan
    <timestamp>-plan.html         the human plan
```

Timestamps prefix the filenames and sort chronologically, so **the latest is the
last one alphabetically**. To pick the current view of a tenant:

- Latest assessment: newest `data/<alias>/assessments/*-assessment.json`.
- Latest plan: newest `data/<alias>/plans/*-plan.json`.
- Latest snapshot: newest `data/<alias>/<timestamp>/` directory.

If `data/` holds more than one alias and the user did not say which, ask. If the
file the user needs does not exist yet, tell them the command that produces it
rather than guessing at its contents:

- No snapshot: `iamai collect <alias>`
- No assessment: `iamai assess <alias>` (after collect)
- No plan: `iamai wizard <alias>` then `iamai plan <alias>` (the wizard answers
  the handful of questions only the operator knows)

## Job A: interpret the graded artifacts

Read `assessment.json` (or `plan.json`), check its `schemaVersion` against what
`ARTIFACTS.md` documents, and answer from its fields. Resolve every identifier
through the record's `names` map so nothing you say disagrees with itself.

Common questions and where the answer lives:

- "How does this tenant stand?" -> `gradeCounts`, then the `controls` with the
  weaker grades. Name specific controls, never a single number.
- "Why did control X get that grade?" -> that control's `coverageGaps`, `notes`,
  and `structural`. Quote them. Do **not** re-derive the grade from raw data.
- "What isn't graded / can't it see?" -> `notApplicable`, `outOfReach`,
  `unknowns`, and `licensing.known`. `outOfReach` controls are never counted
  against the tenant; their `mitigation` says what to do without the licence.
- "What extra policies does the tenant have?" -> `surplus`. Never penalised.
- "What's the plan / what do I do first?" -> `plan.json` `phases`, then `steps`
  in order. For a step, read its `actions`, `verification`, `rollback`, and
  `watchFor` (the cost to users) as written. Honour `notIncluded` and its
  reasons; do not treat an omitted step as an oversight.

## Job B: investigate the raw snapshot

For questions the grades do not answer ("which accounts still lack MFA?", "which
apps have a credential?", "who signed in from where?"), read the raw datasets.
The catalog of every dataset, its shape, and its key fields is in
`reference/datasets.md`. Read it before querying raw data.

Notes that matter:

- Sign-ins are **gzipped JSON Lines** (`signins_*.jsonl.gz`), one event per line.
  Stream them; some tenants have large feeds. The window is bounded (default 30
  days), so absence of an event is not proof it never happened.
- `users.json`, `service_principals.json`, and `roles.json` (144+ role
  definitions) can be large. Filter with `jq` or a small Python read rather than
  loading everything into the reply.
- Check `manifest.json` `complete` first. If a dataset is partial or a collector
  errored, say so; a raw answer drawn from partial data is itself partial.
- Keep the axes straight: something you notice in raw data is an observation. If
  it seems to contradict a grade, present both and point the operator at the
  control; the engine may be seeing a nuance the raw glance misses.

## Staying in your lane

- Read only. This skill and the tool never modify the tenant. Every remediation
  is a document for a person to carry out.
- Do not run `collect`, `assess`, or `plan` on the user's behalf unless they ask;
  those hit the live tenant (collect) or overwrite artifacts. Suggest the command
  and let them run it.
- When the raw data and a grade seem to conflict, or when a question needs a
  judgement the artifacts do not contain, say what the files support and where it
  runs out, rather than filling the gap with a guess.
