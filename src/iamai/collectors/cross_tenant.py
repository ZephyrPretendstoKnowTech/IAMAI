"""Cross-tenant access policy: the default configuration and partner overrides.

Verified: GET /v1.0/policies/crossTenantAccessPolicy/default and
/v1.0/policies/crossTenantAccessPolicy/partners both accept application
permission Policy.Read.All, which the collector already holds, so this
dataset adds no consent cost. A partner configuration's null fields inherit
the default, so trust must be read from both. See ASSUMPTIONS.md note 37.

identitySynchronization is deliberately not expanded: it carries the partner
organisation's display name, which the tool has no use for and the sanitizer
would otherwise have to chase.
"""

from __future__ import annotations

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient, GraphError

ENDPOINT = "/policies/crossTenantAccessPolicy"
API_VERSION = "v1.0"
PERMISSION = "Policy.Read.All"


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    errors: list[str] = []

    default: dict | None
    try:
        default = client.get(f"{API_VERSION}{ENDPOINT}/default")
    except GraphError as exc:
        default = None
        errors.append(f"cross-tenant default configuration unreadable, marked unknown: {exc.code}")

    partners: list | None
    try:
        partners = list(client.get_paged(f"{API_VERSION}{ENDPOINT}/partners"))
    except GraphError as exc:
        partners = None
        errors.append(f"cross-tenant partner configurations unreadable, marked unknown: {exc.code}")

    if default is None and partners is None:
        # Nothing was readable, so the dataset is honestly absent and every
        # control depending on it grades UNKNOWN rather than guessed.
        return Outcome(
            endpoint=f"{ENDPOINT}/default|partners",
            api_version=API_VERSION,
            data=None,
            count=0,
            complete=False,
            errors=errors,
        )

    data = {"default": default, "partners": partners}
    return Outcome(
        endpoint=f"{ENDPOINT}/default|partners",
        api_version=API_VERSION,
        data=data,
        count=(1 if default is not None else 0) + len(partners or []),
        complete=not errors,
        errors=errors,
    )
