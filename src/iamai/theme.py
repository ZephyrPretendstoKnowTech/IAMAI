"""The shared visual foundation for every page IAMAI renders.

One source of truth for the look of the assessment report, the remediation
plan, the questionnaire wizard, and the public demo page, so they read as one
product rather than four. It is plain CSS with no external fonts, images or
scripts, so every page that inlines it stays self-contained: a report opens or
prints with no outbound request, and the wizard serves nothing off the machine.

Templates receive this as a pre-escaped value (`base_css`) and drop it into a
single <style> tag. It is a trusted constant, never tenant data, which is why
it is marked safe here rather than through a template `|safe` filter that a
reviewer would have to re-check.

Design intent: a calm, printable, trustworthy document. Warm neutral paper, a
deep green brand accent, and one semantic colour per grade so the eye can scan
a page of controls without reading every word. Light first, because the
reports are meant to be printed and handed over; the screen pages follow the
same palette.
"""

from __future__ import annotations

from markupsafe import Markup

# --- Design tokens ----------------------------------------------------------
# Changing a value here changes it everywhere. Component rules below refer only
# to these variables, never to raw colours or sizes.
_TOKENS = """
  :root {
    /* Paper and ink */
    --page: #f7f7f4;
    --surface: #ffffff;
    --surface-2: #fbfbf9;
    --ink: #14140f;
    --ink-2: #565550;
    /* Secondary text. Darkened to clear WCAG AA (4.5:1) on white -- the
       earlier #8a887f sat at 3.5:1, which is below AA for normal text. */
    --muted: #726f6a;
    --hairline: rgba(20, 20, 15, 0.10);
    --rule: #e5e4dc;

    /* Brand: a deep, steady green. Used for the wordmark, links, and the
       primary action. */
    --brand: #1f5137;
    --brand-ink: #ffffff;
    --brand-tint: #eef3ee;
    --accent-bar: #2f6b47;

    /* Semantic status. Each grade and risk level maps to exactly one. */
    --ok: #157f3b;
    --ok-tint: #e9f4ec;
    --info: #0f6e6a;
    --info-tint: #e6f2f1;
    --warn: #b7791f;
    --warn-tint: #fbf1de;
    --bad: #c23b3b;
    --bad-tint: #fbeaea;
    --neutral: #6b6a64;
    --neutral-tint: #efefea;

    /* Shape */
    --radius: 10px;
    --radius-sm: 6px;
    --shadow: 0 1px 2px rgba(20, 20, 15, 0.04), 0 1px 8px rgba(20, 20, 15, 0.04);
  }
"""

# --- Reset, typography, page frame ------------------------------------------
_BASE = """
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body {
    margin: 0;
    background: var(--page);
    color: var(--ink);
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    font-size: 15px;
    line-height: 1.6;
  }
  main { max-width: 56rem; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }
  h1 { font-size: 1.65rem; line-height: 1.25; margin: 0 0 0.3rem; letter-spacing: -0.01em; }
  h2 { font-size: 1.2rem; margin: 2.75rem 0 0.85rem; letter-spacing: -0.005em; }
  h3 { font-size: 1rem; margin: 0; }
  h4 { font-size: 0.9rem; margin: 1rem 0 0.25rem; }
  p { margin: 0.45rem 0; }
  a { color: var(--brand); text-underline-offset: 0.15em; }
  strong { font-weight: 650; }
  .eyebrow {
    color: var(--muted);
    font-size: 0.78rem;
    font-weight: 650;
    letter-spacing: 0.07em;
    text-transform: uppercase;
  }
  .meta { color: var(--ink-2); margin-bottom: 1.5rem; }
  .query { color: var(--muted); font-size: 0.85rem; }

  /* A quiet wordmark, so every page is recognisably the same product. */
  .brandbar {
    display: flex; align-items: center; gap: 0.55rem;
    color: var(--brand); font-weight: 700; letter-spacing: 0.02em;
    margin-bottom: 1.75rem;
  }
  .brandbar .mark {
    width: 1.5rem; height: 1.5rem; border-radius: 6px;
    background: var(--brand); color: var(--brand-ink);
    display: inline-flex; align-items: center; justify-content: center;
    font-size: 0.85rem; font-weight: 800;
  }
  .brandbar .sub { color: var(--muted); font-weight: 500; letter-spacing: 0; }
"""

# --- Callouts and stat tiles ------------------------------------------------
_CALLOUTS = """
  .banner, .why {
    background: var(--surface);
    border: 1px solid var(--hairline);
    border-left: 4px solid var(--accent-bar);
    border-radius: var(--radius-sm);
    padding: 0.8rem 1rem;
    margin: 1rem 0;
  }
  .banner strong { display: block; }
  .why { background: var(--brand-tint); border-left-color: var(--brand); font-size: 0.95rem; }

  .tiles {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));
    gap: 0.75rem;
    margin: 1.25rem 0;
  }
  .tile {
    background: var(--surface);
    border: 1px solid var(--hairline);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow);
    padding: 0.85rem 1rem;
    border-top: 3px solid var(--neutral);
  }
  .tile.green { border-top-color: var(--ok); }
  .tile.amber { border-top-color: var(--warn); }
  .tile.red { border-top-color: var(--bad); }
  .tile .status { font-weight: 650; }
  .tile .icon { display: inline-block; width: 1.1em; }
  .tile.green .icon { color: var(--ok); }
  .tile.amber .icon { color: var(--warn); }
  .tile.red .icon { color: var(--bad); }
  .tile .count { color: var(--ink-2); font-size: 0.9rem; }
  .totals { color: var(--ink-2); margin: 0.5rem 0 0; }
  .legend { color: var(--ink-2); font-size: 0.9rem; margin-top: 0.5rem; }
  .legend dt { font-weight: 650; float: left; clear: left; width: 8.5rem; color: var(--ink); }
  .legend dd { margin: 0 0 0.15rem 9rem; }
"""

# --- Cards: one control, or one plan step -----------------------------------
_CARDS = """
  .card {
    background: var(--surface);
    border: 1px solid var(--hairline);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 1.4rem 1.6rem 1.15rem;
    margin: 1.35rem 0;
    break-inside: avoid;
  }
  .card header { display: flex; justify-content: space-between; gap: 1rem; align-items: baseline; }
  .card .title-row { display: flex; gap: 0.6rem; align-items: baseline; margin-top: 0.15rem; }
  .card ul { margin: 0.3rem 0 0.3rem 1.2rem; padding: 0; }
  .card .id { color: var(--muted); font-size: 0.8rem; }

  /* One graded control: a scannable summary line that expands to the full
     detail. A grade-coloured left edge lets the eye run down the page. */
  .control {
    background: var(--surface);
    border: 1px solid var(--hairline);
    border-left-width: 3px;
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    margin: 0.7rem 0;
    break-inside: avoid;
    overflow: hidden;
  }
  .control.green { border-left-color: var(--ok); }
  .control.teal  { border-left-color: var(--info); }
  .control.amber { border-left-color: var(--warn); }
  .control.red   { border-left-color: var(--bad); }
  .control.gray  { border-left-color: var(--neutral); }
  .control > summary {
    cursor: pointer; list-style: none; display: flex; gap: 0.85rem;
    align-items: flex-start; padding: 0.95rem 1.3rem;
  }
  .control > summary:hover { background: var(--surface-2); }
  .control > summary::-webkit-details-marker { display: none; }
  .control > summary::after {
    content: "\\25be"; margin-left: auto; align-self: center;
    color: var(--muted); transition: transform 0.15s ease;
  }
  .control[open] > summary::after { transform: rotate(180deg); }
  .control[open] > summary { border-bottom: 1px solid var(--hairline); }
  .control .grade { flex: none; margin-top: 0.05rem; }
  .control .control-head { display: flex; flex-direction: column; gap: 0.1rem; min-width: 0; }
  .control .control-intent { font-weight: 650; color: var(--ink); line-height: 1.35; }
  .control .control-oneline { color: var(--ink-2); font-size: 0.9rem; }
  .control > .control-body { padding: 0.4rem 1.3rem 1.15rem; color: var(--ink-2); font-size: 0.92rem; }
  .control .rationale { color: var(--ink-2); }
  .control ul { margin: 0.3rem 0 0.3rem 1.2rem; padding: 0; }
  .control .id { color: var(--muted); font-size: 0.8rem; }

  /* A small square marker in front of a plan step's actions. */
  .tick {
    flex: none; display: inline-block; width: 0.85em; height: 0.85em;
    border-radius: 3px; position: relative; top: 0.08em; background: var(--brand);
  }
  ol.actions { padding-left: 1.3rem; }
  ol.actions > li { margin: 0.3rem 0; }
"""

# --- Pill badges: grades and risk levels ------------------------------------
_BADGES = """
  .grade, .risk {
    white-space: nowrap;
    font-size: 0.78rem;
    font-weight: 650;
    border: 1px solid var(--hairline);
    border-radius: 999px;
    padding: 0.12rem 0.65rem 0.12rem 0.5rem;
    background: var(--surface-2);
  }
  .grade .dot, .risk .dot {
    display: inline-block; width: 0.55em; height: 0.55em;
    border-radius: 50%; margin-right: 0.4em; position: relative; top: -0.02em;
  }
  .grade.green .dot { background: var(--ok); }
  .grade.teal .dot  { background: var(--info); }
  .grade.amber .dot { background: var(--warn); }
  .grade.red .dot   { background: var(--bad); }
  .grade.gray .dot  { background: var(--neutral); }
  .grade.green { background: var(--ok-tint); }
  .grade.teal  { background: var(--info-tint); }
  .grade.amber { background: var(--warn-tint); }
  .grade.red   { background: var(--bad-tint); }
  .grade.gray  { background: var(--neutral-tint); }
  .risk.high .dot   { background: var(--bad); }
  .risk.medium .dot { background: var(--warn); }
  .risk.low .dot    { background: var(--ok); }
  .risk.high   { background: var(--bad-tint); }
  .risk.medium { background: var(--warn-tint); }
  .risk.low    { background: var(--ok-tint); }
"""

# --- Tables, disclosure, forms ----------------------------------------------
_ELEMENTS = """
  table { border-collapse: collapse; width: 100%; background: var(--surface); border-radius: var(--radius-sm); overflow: hidden; }
  th, td { text-align: left; padding: 0.5rem 0.8rem; border-bottom: 1px solid var(--rule); vertical-align: top; }
  th { font-weight: 650; background: var(--surface-2); font-size: 0.92rem; }
  td.num { font-variant-numeric: tabular-nums; }
  .table-wrap { overflow-x: auto; }

  details {
    margin: 0.75rem 0;
    border: 1px solid var(--hairline);
    border-radius: var(--radius-sm);
    padding: 0.5rem 0.95rem;
    background: var(--surface-2);
  }
  details summary { cursor: pointer; color: var(--ink-2); font-size: 0.92rem; font-weight: 650; }
  details[open] summary { margin-bottom: 0.4rem; }

  form { margin-top: 1.5rem; }
  .progress { color: var(--muted); font-size: 0.9rem; letter-spacing: 0.02em; }
  .opt {
    display: block; padding: 0.55rem 0.7rem; margin: 0.3rem 0;
    background: var(--surface); border: 1px solid var(--hairline);
    border-radius: var(--radius-sm); cursor: pointer;
  }
  .opt:hover { border-color: var(--brand); }
  .extra { display: block; margin-top: 0.8rem; font-size: 0.9rem; }
  input[type="text"], textarea {
    width: 100%; box-sizing: border-box; padding: 0.5rem; margin-top: 0.3rem;
    border: 1px solid var(--hairline); border-radius: var(--radius-sm);
    font: inherit; background: var(--surface);
  }
  select.dropdown {
    width: 100%; box-sizing: border-box; padding: 0.5rem; margin-top: 0.3rem;
    border: 1px solid var(--hairline); border-radius: var(--radius-sm);
    font: inherit; background: var(--surface); color: var(--ink);
  }
  input[type="text"]:focus, textarea:focus, select.dropdown:focus { outline: 2px solid var(--accent-bar); outline-offset: 1px; }
  button, .btn {
    display: inline-block; margin-top: 1.2rem; padding: 0.62rem 1.5rem;
    font: inherit; font-weight: 650; background: var(--brand); color: var(--brand-ink);
    border: none; border-radius: var(--radius-sm); cursor: pointer; text-decoration: none;
  }
  button:hover, .btn:hover { background: var(--accent-bar); }
  .btn.ghost { background: transparent; color: var(--brand); border: 1px solid var(--hairline); }
  .btn.ghost:hover { background: var(--brand-tint); }
  /* Keyboard focus must be visible on every interactive element, not just
     text inputs (WCAG 2.4.7). :focus-visible keeps mouse clicks ringless. */
  button:focus-visible, .btn:focus-visible, a:focus-visible, .opt:focus-within {
    outline: 2px solid var(--accent-bar); outline-offset: 2px;
  }
  .wizard-nav { display: flex; justify-content: space-between; align-items: center; margin-top: 1rem; }
  .wizard-nav .btn { margin-top: 0; padding: 0.45rem 1rem; }
  .error { background: var(--bad-tint); border-left: 4px solid var(--bad); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); }

  footer {
    margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--rule);
    color: var(--ink-2); font-size: 0.9rem;
  }
  footer .attribution { color: var(--muted); font-size: 0.82rem; margin-top: 0.8rem; }
"""

# --- Print: flatten to plain paper ------------------------------------------
_PRINT = """
  /* Narrow screens: let a wide table scroll within itself rather than push
     the whole page sideways. display:block turns the table into a scroll box;
     it reverts to a normal table above this width and in print. */
  @media (max-width: 40rem) {
    table { display: block; overflow-x: auto; }
    main { padding: 1.75rem 1rem 3rem; }
    .hero h1 { font-size: 1.8rem; }
  }

  @media print {
    body { background: #ffffff; }
    main { max-width: none; padding: 0; }
    .control, .card, .tile, .banner, .why, table, details { background: #ffffff; box-shadow: none; }
    a { color: var(--ink); text-decoration: none; }
    .brandbar { margin-bottom: 1rem; }
    /* A printed report shows everything: force every collapsible open and drop
       the expand affordance so nothing is hidden on paper. */
    details > *:not(summary) { display: block !important; }
    details > summary::after { display: none !important; }
    .control > summary { cursor: default; }
  }
"""

BASE_CSS: str = "".join([_TOKENS, _BASE, _CALLOUTS, _CARDS, _BADGES, _ELEMENTS, _PRINT])


def theme_css() -> Markup:
    """The shared stylesheet, pre-marked safe for direct inlining into a
    <style> tag. Safe because it is this module's own constant, never any
    collected or user-supplied value."""
    return Markup(BASE_CSS)
