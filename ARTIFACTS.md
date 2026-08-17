# The artifact contract

IAMAI writes two JSON artifacts a downstream reader can consume: the assessment
(`data/<alias>/assessments/<timestamp>-assessment.json`) and the plan
(`data/<alias>/plans/<timestamp>-plan.json`). This document is their contract.
It exists so a Claude skill, or any other tool, can read what the engine
produced without guessing at the shape, and without re-deriving or second
guessing the grades.

Machine-readable schemas live in `schemas/assessment.schema.json` and
`schemas/plan.schema.json` (JSON Schema draft 2020-12). A test validates real
output against them, so this document and the schemas stay in agreement.

The examples below use synthetic values (`user1@tenant.example`, placeholder
GUIDs). **The real files are not sanitized:** they name real people and carry
the real tenant id, because they are generated on the operator's own machine
from raw collected data and are meant to be read there. Only a copy produced by
`iamai sanitize` is safe to move off the machine. A consumer that displays or
forwards these artifacts is handling real identities.

## Rules for a consumer

The engine is the only source of truth for grading. A reader of these files:

1. **Reports the numbers the engine computed.** It never re-grades, never
   overrides a grade, never computes its own.
2. **Never invents a control, a finding, or a fix.** Everything it says is
   drawn from these fields. Where a field is empty, the honest answer is that
   there is nothing there, not a guess.
3. **Restates, does not reinterpret.** The `intent`, `rationale`, and plan step
   text are authored to be read aloud as written. Paraphrasing them risks
   turning a careful statement into a wrong one.
4. **Respects the two axes.** `grade` is the security effect. `structural` is a
   separate, advisory axis that never changes a grade. A consumer must not
   present a structural note as a failure.
5. **Respects conservatism.** A grade is never better than the evidence.
   `UNKNOWN` means the data could not judge it, which is not the same as a pass
   or a fail, and must not be shown as either.

## `schemaVersion`

Both artifacts carry an integer `schemaVersion`. The assessment record is
version `1`; the plan record is version `2`; the two are numbered
independently. (The controls inside an assessment were authored under a pack
whose own `schemaVersion` is 2, a third, separate number for the standard pack
format.) A consumer should read the record's `schemaVersion` and refuse a
version it does not understand rather than misread it. New fields may be added
within a version; existing fields keep their meaning.

## assessment.json

Top-level fields:

| Field | Type | Meaning |
|---|---|---|
| `schemaVersion` | int | Contract version of this record. |
| `alias` | string | The operator's short name for the tenant. The only tenant label meant for display. |
| `tenantId` | string (GUID) | The real Entra tenant id. Present in the raw file; absent from a sanitized copy. |
| `generatedAt` | string (ISO 8601) | When the assessment was written. |
| `baseline` | object | `{pack, tool, version}`: which standard and tool version graded this. |
| `gradeCounts` | object | Count per grade that occurred, e.g. `{"FULL": 13, "FUNCTIONAL": 4, "PARTIAL": 13}`. A grade with zero controls may be absent. |
| `controls` | array | One graded control each. See below. |
| `notApplicable` | array | Controls not graded because a condition did not hold (e.g. a check that only applies when a feature is on). `{controlId, intent, note, citations}`. Recorded, never scored. |
| `outOfReach` | array | Controls the tenant cannot license. `{controlId, intent, requires, protects, mitigation, note, citations}`. Never counted against the tenant; `mitigation` says what to do without the licence. |
| `surplus` | array | Policies present in the tenant but outside the standard. `{id, displayName, type, state, note}`. Never penalized. |
| `licensing` | object | `{known: bool, entraP1: bool, entraP2: bool}`. `known` is false when licence data could not be read; absence never excuses a control. |
| `context` | object | Tenant context for the report: `federatedDomains`, `globalAdministrators`, `legacyAuth`, `licenses`, `registration`, `securityDefaultsEnabled`. |
| `names` | object | Display-only lookup: `{guid: displayName}`. Every other field resolves identifiers through this, so nothing else disagrees. Never use it for comparison. |
| `unknowns` | array of string | Plain-language statements of what the data could not see (e.g. a 30-day sign-in window). |
| `scopeNote` | string | A standing statement of what the grading does and does not claim. |

A **control** object:

| Field | Type | Meaning |
|---|---|---|
| `controlId` | string | Stable id, e.g. `cap-001`. |
| `surface` | string | What kind of thing it grades: `conditionalAccess`, `authMethods`, `authMethodsPolicy`, `authenticationStrength`, `registrationCampaign`, `namedLocation`, `authorizationPolicy`, `adminConsentRequestPolicy`, `privilegedAccess`, `securityDefaults`, `crossTenantAccess`, `conditionalAccessCollection`. |
| `grade` | string | One of `FULL`, `FUNCTIONAL`, `PARTIAL`, `MISSING`, `UNKNOWN`. See below. |
| `intent` | string | What the control is for, in plain language. Authored for display. |
| `rationale` | string | Why it matters. Authored for display. |
| `riskClass` | string | `high`, `medium`, or `low`. |
| `profile` | string | `baseline` or `strict`. |
| `coverageGaps` | array of string | Where the tenant falls short of the control, in plain language. Empty when it does not. |
| `notes` | array of string | Other plain-language notes about the grade. |
| `structural` | array of string | The advisory axis: how the tenant's construction differs from the standard's shape. **Never affects the grade.** |
| `matchedPolicies` | array | `{id, displayName}` of the tenant policies that satisfy the control. |
| `affected` | object | `{count, sampleUPNs}`: how many accounts this applies to, with up to five example UPNs. |
| `citations` | array | `{source, item}` mapping to published guidance. A citation is a claim the control covers that item; the report rolls these up into a per-source view. |
| `tenantId` | string | The tenant id, repeated per control. |

### Grades

| Grade | Meaning |
|---|---|
| `FULL` | Matches the standard. |
| `FUNCTIONAL` | Protected, but built differently from the standard. Same security effect, different shape. |
| `PARTIAL` | Present but weaker than the standard. |
| `MISSING` | The protection does not exist in the tenant. |
| `UNKNOWN` | The collected data could not judge it. Never guessed. Not a pass and not a fail. |

## plan.json

Top-level fields:

| Field | Type | Meaning |
|---|---|---|
| `schemaVersion` | int | Contract version. |
| `alias` | string | Tenant label for display. |
| `tenantId` | string (GUID) | Real tenant id (raw file only). |
| `generatedAt` | string | When the plan was written. |
| `basedOnAssessment` | string | The assessment record this plan was built from. |
| `startDate` | string (date) | Day 1 of the rollout, in the operator's timezone. |
| `licenseTier` | string | The tier the plan assumes (`P2`, `P1`, `BusinessPremium`, `none`), from the questionnaire. |
| `phases` | array | `{number, name, purpose, days, dates, gateId}`. The rollout is staged; each phase ends at a checkpoint gate. |
| `gates` | array | `{id, statement, query, extensionRule}`. A checkpoint that must pass before the next phase. |
| `steps` | array | The work. See below. |
| `watchList` | array | `{item, kind, reason}`: things to watch during rollout. |
| `notIncluded` | array | Steps deliberately left out (e.g. a control the licence does not support, or one with no step written yet), each with a reason. |
| `comms` | object | `{announcement, reminder, helpdesk}`: ready-to-send plain-text templates. Rendered into the plan HTML, never sent by the tool. |
| `bestEffortNote` | string | Present when the plan is a best-effort fallback. |
| `unknowns` | array of string | What the plan could not determine. |
| `scopeNote` | string | Standing statement of what the plan is and is not. |

A **step** object:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | `step-01`, ordered. |
| `controlId` | string | The control this step remediates. |
| `title` | string | What the step does. |
| `phase` | int | Which phase it belongs to. |
| `riskClass` | string | `high`/`medium`/`low`. |
| `actions` | array of string | The steps to perform, in order, in plain language. |
| `preconditions` | array | `{statement, query, result}`: what must be true before starting. `result` is `pass`/`fail`/`unverified`. |
| `verification` | object | `{query, expected}`: how to confirm the step worked. |
| `rollback` | array of string | How to undo it. |
| `watchFor` | array of string | What the change will cost the people who use the tenant, stated up front. |
| `affected` | object | `{count, samples}`: who it touches. `count` is 0 for tenant-wide settings this tool cannot enumerate. |
| `lists` | array | Supporting lists (e.g. accounts to onboard), when a step needs them. |

## What is deliberately not here

- **No score or percentage.** The tool grades per control against a conservative
  rubric; it does not roll the grades into a single number, because a number
  invites a target and hides which specific protection is weak.
- **No remediation the tool would perform.** Every step is a document for a
  person to carry out. Nothing in these artifacts is an instruction the tool
  acts on.
- **No raw Graph objects.** These are the engine's conclusions and the authored
  text around them, not a dump of what was collected. The collected data lives
  in the snapshot under `data/<alias>/<timestamp>/raw/`.
