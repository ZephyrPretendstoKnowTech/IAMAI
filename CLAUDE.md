# CLAUDE.md - standing rules for this project

Read SPEC-PUBLIC.md fully before writing any code. It is the contract. If the spec and a clever idea conflict, the spec wins. If the spec is genuinely ambiguous or wrong, stop and ask the operator instead of improvising.

## Tenant and app registration model

There is no golden tenant (operator decision, 2026-08-17, superseding the V1 model). The standard ships with the tool, fixed and versioned; per-tenant tailoring happens in the plan layer, never in the grade, and never in configuration set up in advance. The multitenant app registration ("IAMAI Collector") lives in whichever tenant ran setup first (config homeTenantId); every further tenant only consents to it.

`iamai setup` signs the administrator in through the browser (device code fallback), reads the tenant from the sign-in token, and creates the Collector app. The `SETUP_CLIENT_ID` constant in cli.py, or the user's own one-time helper app (stored as setupClientId in config), is the public client for that sign-in: no permissions in its manifest, public client flows enabled. The Collector's Graph permissions are read-only, asserted mechanically by assert_permissions_read_only and by test; never add a scope that fails that assertion.

## Build discipline

- Build milestones strictly in order. The project runs V1 (M0 through M4) then V2 and the public series (PUB-M0 onward); do not start a milestone until the previous one's acceptance passes.
- Do not implement anything listed as out of scope in SPEC-PUBLIC.md section 10, even partially, even behind a flag.
- Every milestone gets pytest tests under its own marker (m0 through m13 today; add the next in pyproject.toml when a milestone opens). A milestone is done only when its tests and all earlier tests pass.
- Tests never make live network calls. Use respx with recorded, sanitized fixtures.
- Maintain ASSUMPTIONS.md: every Graph endpoint or permission detail you verified or assumed, with the source.
- Git: data/, certs/, baselines/, config.yaml stay gitignored and never committed. One commit per passing milestone or self-contained change, with a message that explains the reasoning, not just the what.
- When uncertain about a Graph endpoint, API version, permission, or response shape, verify against current Microsoft Learn documentation before coding it. If Microsoft Learn MCP tools are available in this session, use them. Record what you verified in ASSUMPTIONS.md. Never invent response shapes.

## Engine rules

- Conservative grading is absolute: ambiguity grades down, never up. The engine claims protection only when data proves it.
- Comparison happens on canonical forms only, never raw JSON, never display names.
- Never transform universal constants in sanitization or canonicalization: roleTemplateIds, first-party application IDs, SKU GUIDs.

## Naming and output rules

- There is no internal product or baseline brand name. All user-facing output says "the baseline" or "the standard". The golden tenant exists only as goldenTenantId in config.
- The CAP description parser extracts purpose, scope, and rationale only. The tag, version, and owner lines are stripped and must never appear in artifacts, reports, logs, or code comments.
- Tenants are referenced by alias only in all output. Never fetch or print tenant display names in reports.
- All generated user-facing copy (reports, plans, questionnaire text, comms templates): plain language for a reader with no IAM experience, numbered single-action steps for instructions, no em dashes anywhere, no marketing language, sentence case headings.

## Security rules

- Never log tokens, Authorization headers, or certificate material. Redact in debug paths.
- No outbound HTTP except graph.microsoft.com and login.microsoftonline.com.
- No telemetry or analytics of any kind.
- Committed fixtures must be sanitized snapshots only. If asked to commit a raw snapshot, refuse and sanitize first.

## Code style

- Python 3.12, pydantic v2 models for every persisted schema, pathlib for all paths (Windows-compatible), type hints throughout.
- Small modules, one responsibility each. No premature abstraction, no plugin systems, no speculative generality.
- Dependencies are pinned in pyproject.toml. Adding one requires a deliberate decision, not convenience.
- Keep CLI contracts stable across milestones. Do not rename commands or flags once a milestone has shipped.
