"""Deterministic pseudonymizer.

Produces a sanitized copy of a snapshot for fixtures and anything pasted into
an AI tool. HMAC-SHA256 with a local salt maps each value to a stable token,
so the same input maps to the same token everywhere in the snapshot
(referential integrity). The mapping lives in data/{alias}/pseudo_map.json,
which is gitignored.

Never transformed (universal constants the engine depends on):
roleTemplateIds, first-party application IDs, Microsoft SKU GUIDs, and policy
structure. Application IDs are preserved only when the app is Microsoft
first-party (documented GUID families, or the snapshot's own service
principal list shows a Microsoft appOwnerOrganizationId); tenant-created
app IDs are identifying and map to stable pseudonyms like any other GUID,
so canonical comparison on appId still holds within a sanitized snapshot.
GUIDs embedded inside longer strings (for example the subscribedSku id,
which is "{tenantId}_{skuId}") are pseudonymized in place under the same
rules (ASSUMPTIONS.md note 20).
"""

from __future__ import annotations

import gzip
import io
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import uuid
from pathlib import Path

# Values under these keys are universal identifiers the parity engine compares
# on. They are never pseudonymized.
#
# Adding a key here is a security decision, not a convenience. A GUID seen once
# under any of these keys is preserved everywhere it appears in the snapshot,
# so a key whose values are tenant specific would leak those values through
# every other field as well (BUGS.md item 18). Only add a key whose values are
# Microsoft published constants, identical in every tenant. test_m0_sanitize
# pins this set so the change cannot be made without meaning it.
#
# A guard that simply refused to preserve any GUID which is also an object id
# in the tenant was considered and rejected: a built-in role definition's id
# equals its template id, so that guard would break role preservation, which
# is the main thing this set exists for.
UNIVERSAL_KEYS = frozenset(
    {
        "roleTemplateId",
        "templateId",
        "includeRoles",
        "excludeRoles",
        "skuId",
        "servicePlanId",
        "skuPartNumber",
        "servicePlanName",
    }
)

# Values under these keys are application IDs: universal only when the app is
# Microsoft first-party, tenant-identifying otherwise.
APP_ID_KEYS = frozenset(
    {
        "appId",
        "includeApplications",
        "excludeApplications",
        "resourceId",
        "resourceAppId",
        "appOwnerOrganizationId",
    }
)

# Owner tenants of Microsoft first-party service principals: Microsoft
# Services and Microsoft Corporation (Source: learn.microsoft.com
# troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in).
MS_OWNER_TENANT_IDS = frozenset(
    {
        "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
        "72f988bf-86f1-41af-91ab-2d7cd011db47",
    }
)

# The two documented first-party appId families: the Office 365 workload
# family (…-0000-0ff1-ce00-…) and the classic Microsoft services family
# (…-0000-0000-c000-000000000000, e.g. Microsoft Graph).
_FIRST_PARTY_APP_RE = re.compile(
    r"^[0-9a-f]{8}-0000-0ff1-ce00-000000000000$"
    r"|^[0-9a-f]{8}-0000-0000-c000-000000000000$",
    re.IGNORECASE,
)

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_GUID_ANY_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Embedded forms, for values that merely contain an address or an IP rather
# than being one (BUGS.md item 16).
_EMAIL_ANY_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4_ANY_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Tenant identity that is not an email, GUID or IP and so was never matched by
# any pattern pass. CLAUDE.md forbids tenant display names in output, and a
# postal address identifies a tenant just as well (BUGS.md item 15).
_TENANT_IDENTITY_KEYS = frozenset({
    "street", "city", "state", "postalCode", "businessPhones",
    "marketingNotificationEmails", "securityComplianceNotificationMails",
    "securityComplianceNotificationPhones",
    # Every subscribedSkus record carries the tenant's own name here. The
    # displayName rule below did not reach it, because a licence record does
    # not look like an organization object, so the tenant name survived every
    # sanitized snapshot and reached a committed test fixture. Found by running
    # a secret scanner over the full history before publishing.
    "accountName",
})

_USER_NAME_KEYS = frozenset({"userDisplayName"})

_NAME_LABELS = {"user": "User", "group": "Group", "device": "Device"}

# Objects nulled out entirely rather than pattern-scrubbed, because their
# value is precision-sensitive data with no string form for the pattern
# passes to catch: geoCoordinates is a pair of floats, not text, so the
# type-dispatch in sanitize_node() passed it through unchanged while the
# plain-text city/state sitting next to it was correctly redacted (found by
# running a secret scanner over the full history before publishing: a real
# sign-in's coordinates survived into a committed fixture). Nulling matches
# what Graph itself returns when it cannot resolve a precise location.
_NULLED_OBJECT_KEYS = frozenset({"geoCoordinates"})

# Sign-in events are the one feed pulled as the full Graph object with no
# $select, so they carry the widest, least predictable set of fields -- and
# sanitize_node's key-allowlist transforms only the fields it recognises,
# passing everything else through. That is how a phone number in
# signInIdentifier, a tenant name in homeTenantName, or an int like
# autonomousSystemNumber would survive into a "sanitized" copy (SANITIZE-001,
# CRYPTO-2-001). For this feed the sanitizer fails safe instead: a sign-in
# event is reduced to this keep-list before sanitize_node runs, so any field
# not named here is dropped rather than risked. The engine only reads
# clientAppUsed, userPrincipalName, userId and ipAddress; the rest are kept
# because they are non-personal structure useful when the snapshot is shared
# for analysis. Nested personal data under a kept key (location, deviceDetail)
# is still handled by sanitize_node's existing rules. Deliberately excluded:
# signInIdentifier, alternateSignInName, homeTenantName, autonomousSystemNumber.
_SIGNIN_KEEP = frozenset({
    # Read by the grading engine and questionnaire.
    "clientAppUsed", "userPrincipalName", "userId", "ipAddress",
    # Identity and correlation (pseudonymized by sanitize_node).
    "id", "correlationId", "userDisplayName",
    # Application and resource (structure; GUIDs pseudonymized as needed).
    "appId", "appDisplayName", "resourceId", "resourceDisplayName",
    "servicePrincipalId", "servicePrincipalName",
    # Tenant context (GUIDs pseudonymized).
    "homeTenantId", "resourceTenantId",
    # Conditional Access, risk and status (analysis, non-personal).
    "conditionalAccessStatus", "appliedConditionalAccessPolicies",
    "riskState", "riskDetail", "riskLevelAggregated", "riskLevelDuringSignIn",
    "riskEventTypes", "riskEventTypes_v2", "status",
    "isInteractive", "createdDateTime", "userAgent",
    # Device and location (nested personal data handled by sanitize_node).
    "deviceDetail", "location",
})

_SANITIZED_DOMAIN = "tenant.example"


def _parse_ip(value: str) -> tuple[str, str, int] | None:
    """Return (base, prefix, ip_version) when value is an IP or CIDR."""
    base, _, prefix = value.partition("/")
    try:
        parsed = ipaddress.ip_address(base)
    except ValueError:
        return None
    return base, prefix, parsed.version


class Pseudonymizer:
    """Stable value-to-token mapping backed by pseudo_map.json."""

    def __init__(self, map_path: Path):
        self.map_path = map_path
        if map_path.exists():
            state = json.loads(map_path.read_text(encoding="utf-8"))
        else:
            state = {
                "salt": secrets.token_hex(32),
                "emails": {},
                "names": {},
                "guids": {},
                "ips": {},
                "domains": {},
            }
        self._state = state
        self._salt = bytes.fromhex(state["salt"])
        self._verified_domains: list[str] = []
        self._domains_by_len: list[str] = []
        # Per-kind name counters, seeded from any loaded map so re-runs keep
        # numbering, so map_name does not rescan the whole name table on every
        # new value (PERF-2-006).
        self._name_counts: dict[str, int] = {}
        for existing in state["names"]:
            kind = existing.split(":", 1)[0]
            self._name_counts[kind] = self._name_counts.get(kind, 0) + 1
        # Same idea for IP tokens: hold the next index per family so map_ip
        # allocates in O(1) instead of rescanning every prior token, which was
        # O(n^2) over a real sign-in feed's tens of thousands of addresses.
        self._ip_v6_next = 0
        self._ip_v4_next = 0
        for token in state["ips"].values():
            if token.startswith("2001:db8"):
                self._ip_v6_next += 1
            else:
                self._ip_v4_next += 1
        # Populated per snapshot before sanitizing: lowercased GUID values
        # that must survive inside composite strings, and first-party appIds
        # proven by the snapshot's own service principal ownership.
        self.universal_guids: set[str] = set()
        self.first_party_appids: set[str] = set()
        # Turned off while walking the sign-in feeds; see map_guid.
        self.record_guids = True

    @property
    def verified_domains(self) -> list[str]:
        return self._verified_domains

    @verified_domains.setter
    def verified_domains(self, domains: list[str]) -> None:
        # Cache the length-descending order sanitize_string needs, so it is not
        # re-sorted on every one of the 100k+ string values in a snapshot. This
        # is the same order the replacement loop already used, so tokens are
        # unchanged (PERF-2-005).
        self._verified_domains = domains
        self._domains_by_len = sorted(domains, key=len, reverse=True)

    @property
    def domains_by_len(self) -> list[str]:
        return self._domains_by_len

    def is_first_party_app(self, value: str) -> bool:
        lowered = value.lower()
        return lowered in self.first_party_appids or bool(_FIRST_PARTY_APP_RE.match(lowered))

    def keep_guid(self, value: str) -> bool:
        """True when a GUID is a universal constant that must not be mapped."""
        lowered = value.lower()
        return (
            lowered in self.universal_guids
            or lowered in MS_OWNER_TENANT_IDS
            or self.is_first_party_app(lowered)
        )

    def save(self) -> None:
        self.map_path.parent.mkdir(parents=True, exist_ok=True)
        # This file holds the salt and the complete reverse map that turns any
        # shared sanitized copy back into real identities, so it is as
        # sensitive as the data it protects. Written owner-only, matching the
        # private key's treatment, rather than at the default umask
        # (CRYPTO-2-003).
        payload = json.dumps(self._state, indent=2, sort_keys=True)
        fd = os.open(self.map_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
        # os.open only applies the mode on creation; a map written before this
        # hardening would keep its looser mode, so tighten unconditionally on
        # POSIX (the mode is a no-op on Windows).
        if os.name != "nt":
            os.chmod(self.map_path, 0o600)

    def _hmac(self, value: str) -> bytes:
        return hmac.new(self._salt, value.encode("utf-8"), hashlib.sha256).digest()

    def map_email(self, value: str) -> str:
        table = self._state["emails"]
        if value not in table:
            table[value] = f"user{len(table) + 1}@{_SANITIZED_DOMAIN}"
        return table[value]

    def map_name(self, value: str, kind: str) -> str:
        table = self._state["names"]
        token_key = f"{kind}:{value}"
        if token_key not in table:
            count = self._name_counts.get(kind, 0) + 1
            self._name_counts[kind] = count
            label = _NAME_LABELS.get(kind, kind.title())
            table[token_key] = f"{label} {count}"
        return table[token_key]

    def map_guid(self, value: str) -> str:
        table = self._state["guids"]
        key = value.lower()
        if key in table:
            return table[key]
        token = str(uuid.UUID(bytes=self._hmac(key)[:16], version=4))
        # The token is fully determined by the salt and the value, so storing
        # it is only for the operator's reverse lookup, not for referential
        # integrity. Sign-in events carry a fresh id and correlationId apiece,
        # and recording those grew the map by thousands of entries per collect
        # for identifiers nobody will ever look up (BUGS.md item 34).
        if self.record_guids:
            table[key] = token
        return token

    def map_ip(self, value: str, version: int) -> str:
        table = self._state["ips"]
        token = table.get(value)
        if token is not None:
            return token
        if version == 6:
            # 2001:db8::/32 is the IPv6 documentation range: 2**96 addresses,
            # so it never runs out.
            self._ip_v6_next += 1
            token = f"2001:db8::{self._ip_v6_next:x}"
        else:
            token = self._next_ipv4()
        table[value] = token
        return token

    def _next_ipv4(self) -> str:
        """Allocate the next pseudonymous IPv4, sequentially so distinct real
        addresses never collide onto one fake. The two RFC 5737 documentation
        /24s (508 hosts) come first, so a small snapshot reads with familiar
        example IPs. A real sign-in feed routinely holds far more than 508
        distinct addresses, so overflow continues into 198.18.0.0/15, the RFC
        2544 benchmarking range: also non-routable and non-identifying, and big
        enough (131072 hosts) that no single tenant's window exhausts it."""
        index = self._ip_v4_next
        self._ip_v4_next += 1
        if index < 254:
            return f"203.0.113.{index + 1}"
        if index < 508:
            return f"198.51.100.{index - 253}"
        offset = index - 508
        if offset >= 131072:  # 198.18.0.0/15 is full: ~131580 distinct IPs seen
            raise ValueError(
                "More than 131580 distinct IPv4 addresses in one snapshot; the "
                "documentation and benchmarking ranges are exhausted. This is far "
                "beyond a normal tenant and likely indicates malformed input."
            )
        return f"198.{18 + (offset >> 16)}.{(offset >> 8) & 0xFF}.{offset & 0xFF}"

    def map_domain(self, value: str) -> str:
        table = self._state["domains"]
        key = value.lower()
        if key not in table:
            number = len(table) + 1
            table[key] = _SANITIZED_DOMAIN if number == 1 else f"tenant{number}.example"
        return table[key]


def _looks_like_user_object(obj: dict) -> bool:
    return "userPrincipalName" in obj or "userType" in obj


def _looks_like_group_object(obj: dict) -> bool:
    return "groupTypes" in obj or "securityEnabled" in obj


def _looks_like_device_object(obj: dict) -> bool:
    """A sign-in's deviceDetail block. Its displayName defaults to
    "<Owner's Name>'s <device>" on every major OS, so it carries a real
    person's name on nearly every sign-in event, not just occasionally."""
    return "deviceId" in obj or "operatingSystem" in obj or "trustType" in obj


def _looks_like_address_block(obj: dict | None) -> bool:
    """"state" collides with the key Conditional Access policies and
    authentication method configurations use for their own enablement status
    ("enabled"/"disabled"/"enabledForReportingButNotEnforced"), an identical
    key name with an unrelated meaning. Unlike every other
    _TENANT_IDENTITY_KEYS entry, "state" is ambiguous on its own, so it is
    only treated as a US state/province when a sibling address field or the
    organization object itself confirms the context -- the same way
    displayName is disambiguated by parent shape below. Found by running the
    fixed sanitizer over a real Conditional Access policy: every policy's
    state came back "redacted" instead of "enabled" or "disabled", silently
    destroying whether the policy does anything at all."""
    if obj is None:
        return False
    return "city" in obj or "street" in obj or "postalCode" in obj or _looks_like_organization(obj)


def sanitize_string(pseudo: Pseudonymizer, value: str) -> str:
    """Sanitize one string value by pattern: email, GUID, IP, verified domain,
    then GUIDs embedded inside longer strings (composite ids)."""
    if _EMAIL_RE.match(value):
        return pseudo.map_email(value)
    if _GUID_RE.match(value):
        return value if pseudo.keep_guid(value) else pseudo.map_guid(value)
    ip_parts = _parse_ip(value)
    if ip_parts is not None:
        base, prefix, version = ip_parts
        token = pseudo.map_ip(base, version)
        return f"{token}/{prefix}" if prefix else token
    lowered = value.lower()
    # Longest first, so payroll.contoso.com is replaced before contoso.com and
    # the subdomain label cannot leak (BUGS.md item 17).
    for domain in pseudo.domains_by_len:
        if domain in lowered:
            replacement = pseudo.map_domain(domain)
            value = re.sub(re.escape(domain), replacement, value, flags=re.IGNORECASE)
            lowered = value.lower()

    value = _EMAIL_ANY_RE.sub(lambda m: pseudo.map_email(m.group(0)), value)
    value = _IPV4_ANY_RE.sub(lambda m: pseudo.map_ip(m.group(0), 4), value)

    def _embedded(match: re.Match) -> str:
        guid = match.group(0)
        return guid if pseudo.keep_guid(guid) else pseudo.map_guid(guid)

    return _GUID_ANY_RE.sub(_embedded, value)


def _sanitize_app_id(pseudo: Pseudonymizer, key: str, value: str) -> str:
    """App-id-keyed strings: keep universal tokens ("All", "Office365") and
    first-party ids; map tenant-created ids to stable pseudonyms."""
    if not _GUID_RE.match(value):
        return value
    if key == "appOwnerOrganizationId":
        return value if value.lower() in MS_OWNER_TENANT_IDS else pseudo.map_guid(value)
    return value if pseudo.is_first_party_app(value) else pseudo.map_guid(value)


def _looks_like_organization(obj: dict) -> bool:
    return "verifiedDomains" in obj or "tenantType" in obj


def _sanitize_key(pseudo: Pseudonymizer, key):
    """Dict keys carry data too. transitiveMemberCounts is keyed by real group
    object ids, which both leaked and broke the join to the sanitized group
    list (BUGS.md item 13)."""
    if isinstance(key, str) and _GUID_RE.match(key):
        return key if pseudo.keep_guid(key) else pseudo.map_guid(key)
    return key


def sanitize_node(pseudo: Pseudonymizer, node, parent: dict | None = None, key: str | None = None):
    if key in _NULLED_OBJECT_KEYS:
        return None
    if isinstance(node, dict):
        return {
            _sanitize_key(pseudo, k): sanitize_node(pseudo, v, node, k)
            for k, v in node.items()
        }
    if isinstance(node, list):
        if key in UNIVERSAL_KEYS:
            return list(node)
        if key in APP_ID_KEYS:
            return [
                _sanitize_app_id(pseudo, key, item) if isinstance(item, str) else item
                for item in node
            ]
        return [sanitize_node(pseudo, item, parent, key) for item in node]
    if isinstance(node, str):
        if key in UNIVERSAL_KEYS:
            return node
        if key in APP_ID_KEYS:
            return _sanitize_app_id(pseudo, key, node)
        if key in _USER_NAME_KEYS:
            return pseudo.map_name(node, "user")
        if key in _TENANT_IDENTITY_KEYS and (key != "state" or _looks_like_address_block(parent)):
            return "redacted"
        if key == "displayName" and parent is not None:
            if _looks_like_user_object(parent):
                return pseudo.map_name(node, "user")
            if _looks_like_group_object(parent):
                return pseudo.map_name(node, "group")
            if _looks_like_organization(parent):
                # The tenant's own name. CLAUDE.md: alias only, never the
                # display name (BUGS.md item 15).
                return "The tenant"
            if _looks_like_device_object(parent):
                return pseudo.map_name(node, "device")
            # Policy, strength, location, role, and SP names stay readable
            # because they are structure, not personal data. They still go
            # through the pattern passes, because a name can contain a domain,
            # an address, an IP or a GUID (BUGS.md item 12).
            return sanitize_string(pseudo, node)
        return sanitize_string(pseudo, node)
    return node


def _collect_preserve_sets(pseudo: Pseudonymizer, raw_dir: Path) -> None:
    """Pre-pass: gather universal GUIDs (values under UNIVERSAL_KEYS) and
    first-party appIds (service principals owned by a Microsoft tenant) so
    composite strings and appId fields can be sanitized value-aware."""

    def walk(node, key: str | None = None) -> None:
        if isinstance(node, dict):
            owner = str(node.get("appOwnerOrganizationId", "")).lower()
            app_id = str(node.get("appId", "")).lower()
            if owner in MS_OWNER_TENANT_IDS and _GUID_RE.match(app_id):
                pseudo.first_party_appids.add(app_id)
            for k, v in node.items():
                walk(v, k)
        elif isinstance(node, list):
            for item in node:
                walk(item, key)
        elif isinstance(node, str) and key in UNIVERSAL_KEYS and _GUID_RE.match(node):
            pseudo.universal_guids.add(node.lower())

    for raw_file in sorted(raw_dir.iterdir()):
        if raw_file.suffix == ".json":
            walk(json.loads(raw_file.read_text(encoding="utf-8")))


def _load_verified_domains(raw_dir: Path) -> list[str]:
    """Verified domain names, custom domains first so the primary custom
    domain maps to tenant.example."""
    domains_path = raw_dir / "domains.json"
    if not domains_path.exists():
        # Returning an empty list here silently disabled every domain
        # replacement while the command still reported success, so one failed
        # domains pull produced an unsafe artifact that looked clean
        # (BUGS.md item 14).
        raise FileNotFoundError(
            "This snapshot has no domains.json, so the tenant's domain names "
            "cannot be masked and the sanitized copy would still contain them. "
            "Re-run 'iamai collect' for this tenant and sanitize the new "
            "snapshot."
        )
    payload = json.loads(domains_path.read_text(encoding="utf-8"))
    items = payload if isinstance(payload, list) else payload.get("value", [])
    verified = [
        str(item["id"]).lower()
        for item in items
        if item.get("isVerified") and item.get("id")
    ]
    return sorted(verified, key=lambda name: (name.endswith(".onmicrosoft.com"), name))


def sanitize_snapshot(snapshot_dir: Path, map_path: Path) -> Path:
    """Write a pseudonymized copy of a snapshot to {snapshot}/sanitized/."""
    raw_dir = snapshot_dir / "raw"
    out_dir = snapshot_dir / "sanitized"
    out_dir.mkdir(exist_ok=True)

    pseudo = Pseudonymizer(map_path)
    pseudo.verified_domains = _load_verified_domains(raw_dir)
    _collect_preserve_sets(pseudo, raw_dir)

    for raw_file in sorted(raw_dir.iterdir()):
        if raw_file.suffix == ".json":
            data = json.loads(raw_file.read_text(encoding="utf-8"))
            sanitized = sanitize_node(pseudo, data)
            (out_dir / raw_file.name).write_text(
                json.dumps(sanitized, indent=2, sort_keys=True, ensure_ascii=False),
                encoding="utf-8",
            )
        elif raw_file.name.endswith(".jsonl.gz"):
            with gzip.open(raw_file, "rt", encoding="utf-8") as source, gzip.GzipFile(
                out_dir / raw_file.name, "wb", mtime=0
            ) as _raw, io.TextIOWrapper(_raw, encoding="utf-8", newline="\n") as target:
                pseudo.record_guids = False
                try:
                    for line in source:
                        line = line.strip()
                        if not line:
                            continue
                        raw_event = json.loads(line)
                        # Fail safe: keep only known fields, so an unrecognised
                        # one is dropped rather than passed through unsanitized
                        # (CRYPTO-2-001).
                        kept = {k: v for k, v in raw_event.items() if k in _SIGNIN_KEEP}
                        event = sanitize_node(pseudo, kept)
                        target.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")
                finally:
                    pseudo.record_guids = True

    manifest_path = snapshot_dir / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        (out_dir / "manifest.json").write_text(
            json.dumps(sanitize_node(pseudo, manifest), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    pseudo.save()
    return out_dir
