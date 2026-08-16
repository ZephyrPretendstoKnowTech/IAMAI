"""Sign-in logs, last N days (default 30), interactive and non-interactive.

The two feeds are separate and queried explicitly:

- Interactive: GET /v1.0/auditLogs/signIns with createdDateTime filters.
  The v1.0 endpoint returns only interactive user sign-ins.
- Non-interactive: GET /beta/auditLogs/signIns with the same filters plus
  signInEventTypes/any(t: t eq 'nonInteractiveUser'). The signInEventTypes
  filter exists only on the beta endpoint; Microsoft's own guidance uses beta
  for this feed. Recorded in ASSUMPTIONS.md per SPEC section 4.

Both feeds are pulled in one-day createdDateTime slices because the live
backend times out on wide scan windows (ASSUMPTIONS.md note 19).

Application permission AuditLog.Read.All. Volume is high: stored as
jsonl.gz, paged via @odata.nextLink, Retry-After honored by the client.
appliedConditionalAccessPolicies and sessionLifetimePolicies arrive on each
event because the app also holds Policy.Read.All.
"""

from __future__ import annotations

import gzip
import io
import json
import time
from pathlib import Path

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient

ENDPOINT = "/auditLogs/signIns"
API_VERSION = "v1.0 (interactive) + beta (non-interactive)"
PERMISSION = "AuditLog.Read.All"

INTERACTIVE_FILE = "signins_interactive.jsonl.gz"
NONINTERACTIVE_FILE = "signins_noninteractive.jsonl.gz"

# The signIns backend's per-request cost scales with scan window times page
# fill target: measured live, an unbounded 30-day filter 504s server-side at
# any large $top, while a one-day bounded window returns its whole day in one
# $top=999 page in ~5s on both feeds. Each feed is therefore pulled in one-day
# createdDateTime slices, each a small independently-retried request
# (ASSUMPTIONS.md note 19). Docs cap $top at 1000.
PAGE_SIZE = "999"


def _fmt(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _slice_filters(days: int, now: float, extra: str) -> list[str]:
    """Half-open one-day [ge, lt) windows, oldest first; the newest is
    unbounded above so events landing mid-collect are not missed."""
    filters = []
    for d in range(days, 0, -1):
        expr = f"createdDateTime ge {_fmt(now - d * 86400)}"
        if d > 1:
            expr += f" and createdDateTime lt {_fmt(now - (d - 1) * 86400)}"
        if extra:
            expr += f" and {extra}"
        filters.append(expr)
    return filters


def _stream_feed(client: GraphClient, url: str, slice_filters: list[str], target: Path) -> int:
    count = 0
    # mtime=0 and an explicit newline keep the bytes reproducible: gzip writes
    # the current time into its header, so two collects of an unchanged tenant
    # could never produce identical files (BUGS.md item 31).
    with gzip.GzipFile(target, "wb", mtime=0) as _raw, io.TextIOWrapper(
        _raw, encoding="utf-8", newline="\n"
    ) as out:
        for filter_expr in slice_filters:
            for event in client.get_paged(url, params={"$filter": filter_expr, "$top": PAGE_SIZE}):
                out.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")
                count += 1
    return count


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    now = time.time()
    since = _fmt(now - context.days * 86400)

    interactive_path = context.writer.raw_file_path(INTERACTIVE_FILE)
    noninteractive_path = context.writer.raw_file_path(NONINTERACTIVE_FILE)

    interactive_count = _stream_feed(
        client, f"v1.0{ENDPOINT}", _slice_filters(context.days, now, ""), interactive_path
    )
    noninteractive_count = _stream_feed(
        client,
        f"beta{ENDPOINT}",
        _slice_filters(context.days, now, "signInEventTypes/any(t: t eq 'nonInteractiveUser')"),
        noninteractive_path,
    )

    return Outcome(
        endpoint=f"{ENDPOINT} (interactive v1.0; non-interactive beta, "
        f"signInEventTypes filter), window {context.days} days since {since} "
        f"in one-day slices",
        api_version=API_VERSION,
        data=None,
        count=interactive_count + noninteractive_count,
        files=[f"raw/{INTERACTIVE_FILE}", f"raw/{NONINTERACTIVE_FILE}"],
    )
