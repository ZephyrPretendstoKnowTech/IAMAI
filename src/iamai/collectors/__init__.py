"""Collector framework.

One module per dataset. Each collector returns an Outcome; the runner times
it, writes its data through the snapshot writer, and records a manifest entry
with endpoint, API version, item count, duration, completeness flag, and
errors. A failing collector marks the snapshot partial instead of aborting
the whole collect.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from iamai import __version__
from iamai.graphclient import GraphClient
from iamai.store import DatasetRecord, Manifest, SnapshotWriter


@dataclass
class CollectContext:
    writer: SnapshotWriter
    days: int = 30
    results: dict[str, "Outcome"] = field(default_factory=dict)


@dataclass
class Outcome:
    endpoint: str
    api_version: str
    data: object = None
    count: int = 0
    complete: bool = True
    skipped: bool = False
    errors: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)


from iamai.collectors import (  # noqa: E402  (registry import after framework types)
    admin_consent_request_policy,
    auth_methods_policy,
    auth_strengths,
    authorization_policy,
    cap_policies,
    domains,
    groups,
    named_locations,
    org_licenses,
    registration_details,
    risky_users,
    roles,
    security_defaults,
    service_principals,
    signins,
    users,
)

# Run order matters: groups needs CAP policies and the auth methods policy to
# find referenced group ids; risky_users needs org_licenses for P2 detection.
COLLECTORS: list[tuple[str, object]] = [
    ("conditional_access_policies", cap_policies),
    ("named_locations", named_locations),
    ("auth_strengths", auth_strengths),
    ("auth_methods_policy", auth_methods_policy),
    ("security_defaults", security_defaults),
    ("authorization_policy", authorization_policy),
    ("admin_consent_request_policy", admin_consent_request_policy),
    ("users", users),
    ("registration_details", registration_details),
    ("roles", roles),
    ("groups", groups),
    ("service_principals", service_principals),
    ("org_licenses", org_licenses),
    ("domains", domains),
    ("signins", signins),
    ("risky_users", risky_users),
]


def run_all(
    client: GraphClient,
    writer: SnapshotWriter,
    alias: str,
    days: int = 30,
    progress: Callable[[str, str, int, int], None] | None = None,
) -> Manifest:
    """Run every collector in order and write an immutable snapshot.

    ``progress``, if given, is called as ``progress(event, dataset, index,
    total)`` with ``event`` "start" just before each collector runs and "done"
    just after, so a caller can show live feedback during the long network
    phase. It must not raise; the collect does not depend on it.
    """
    context = CollectContext(writer=writer, days=days)
    records: list[DatasetRecord] = []
    total = len(COLLECTORS)

    for index, (dataset_name, module) in enumerate(COLLECTORS, start=1):
        if progress is not None:
            progress("start", dataset_name, index, total)
        started = time.monotonic()
        try:
            outcome: Outcome = module.collect(client, context)
        except Exception as exc:  # a failed dataset marks the pull partial
            outcome = Outcome(
                endpoint=getattr(module, "ENDPOINT", "unknown"),
                api_version=getattr(module, "API_VERSION", "unknown"),
                complete=False,
                errors=[f"{type(exc).__name__}: {exc}"],
            )
        duration = time.monotonic() - started
        if progress is not None:
            progress("done", dataset_name, index, total)

        files = list(outcome.files)
        if outcome.data is not None:
            writer.write_dataset(dataset_name, outcome.data)
            files.append(f"raw/{dataset_name}.json")

        context.results[dataset_name] = outcome
        records.append(
            DatasetRecord(
                dataset=dataset_name,
                endpoint=outcome.endpoint,
                apiVersion=outcome.api_version,
                count=outcome.count,
                durationSeconds=round(duration, 3),
                complete=outcome.complete,
                skipped=outcome.skipped,
                errors=outcome.errors,
                files=files,
            )
        )

    manifest = Manifest(
        tenantId=client.tenant_id,
        alias=alias,
        collectedAt=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        tool=__version__,
        complete=all(record.complete or record.skipped for record in records),
        datasets=records,
    )
    writer.finalize(manifest)
    return manifest
