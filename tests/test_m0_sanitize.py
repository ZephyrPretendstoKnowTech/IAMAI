import gzip
import json

import pytest

from iamai.sanitize import sanitize_snapshot

pytestmark = pytest.mark.m0

ROLE_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
FIRST_PARTY_APP = "00000002-0000-0ff1-ce00-000000000000"
SKU = "06ebc4ee-1bb5-47dd-8120-11324bc54e06"
PLAN = "eec0eb4f-6444-4f95-aba0-50c24d67f998"
USER_GUID = "20000000-0000-0000-0000-000000000001"
GROUP_GUID = "30000000-0000-0000-0000-000000000001"
TENANT_GUID = "11111111-1111-1111-1111-111111111111"
# Graph Explorer: Microsoft-owned but outside the two first-party GUID
# families, so only the ownership scan can classify it.
MSFT_OWNED_APP = "de8bc8b5-d9f9-48b1-a8ad-b748da725064"
MS_SERVICES_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
TENANT_OWNED_APP = "80000000-0000-0000-0000-000000000001"


@pytest.fixture
def snapshot(tmp_path):
    """A small raw snapshot exercising every transform rule."""
    snapshot_dir = tmp_path / "data" / "golden" / "20260610T000000Z"
    raw = snapshot_dir / "raw"
    raw.mkdir(parents=True)

    (raw / "domains.json").write_text(json.dumps([
        {"id": "contoso.com", "isVerified": True, "authenticationType": "Managed"},
        {"id": "contoso.onmicrosoft.com", "isVerified": True, "authenticationType": "Managed"},
    ]))
    (raw / "users.json").write_text(json.dumps([
        {
            "id": USER_GUID,
            "userPrincipalName": "alice@contoso.com",
            "displayName": "Alice Example",
            "userType": "Member",
        }
    ]))
    (raw / "conditional_access_policies.json").write_text(json.dumps([
        {
            "id": "40000000-0000-0000-0000-000000000001",
            "displayName": "CA001 Require MFA for all users",
            "state": "enabled",
            "conditions": {
                "users": {
                    "includeUsers": ["All"],
                    "excludeUsers": [USER_GUID],
                    "excludeGroups": [GROUP_GUID],
                    "includeRoles": [ROLE_TEMPLATE],
                    "excludeRoles": [],
                },
                "applications": {
                    "includeApplications": ["All"],
                    "excludeApplications": [FIRST_PARTY_APP],
                },
            },
        }
    ]))
    (raw / "roles.json").write_text(json.dumps({
        "roleDefinitions": [
            {"id": ROLE_TEMPLATE, "templateId": ROLE_TEMPLATE, "displayName": "Global Administrator"}
        ],
        "roleAssignments": [
            {"id": "70000000-0000-0000-0000-000000000001", "roleDefinitionId": ROLE_TEMPLATE, "principalId": USER_GUID}
        ],
    }))
    (raw / "org_licenses.json").write_text(json.dumps({
        "subscribedSkus": [
            {"id": f"{TENANT_GUID}_{SKU}",
             "skuId": SKU, "skuPartNumber": "ENTERPRISEPREMIUM",
             "servicePlans": [{"servicePlanId": PLAN, "servicePlanName": "AAD_PREMIUM_P2"}]}
        ]
    }))
    (raw / "service_principals.json").write_text(json.dumps([
        {"appId": MSFT_OWNED_APP, "displayName": "Graph Explorer",
         "appOwnerOrganizationId": MS_SERVICES_TENANT},
        {"appId": TENANT_OWNED_APP, "displayName": "IAMAI Collector",
         "appOwnerOrganizationId": TENANT_GUID},
    ]))
    (raw / "named_locations.json").write_text(json.dumps([
        {"id": "50000000-0000-0000-0000-000000000001",
         "ipRanges": [{"cidrAddress": "131.107.1.0/24"}, {"cidrAddress": "131.107.2.0/24"}]}
    ]))
    with gzip.open(raw / "signins_interactive.jsonl.gz", "wt", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "id": "60000000-0000-0000-0000-000000000001",
            "userPrincipalName": "alice@contoso.com",
            "userDisplayName": "Alice Example",
            "userId": USER_GUID,
            "ipAddress": "131.107.1.5",
            "clientAppUsed": "Browser",
            "resourceId": FIRST_PARTY_APP,
            "appId": FIRST_PARTY_APP,
            # Leak vectors the keep-list must drop: a phone number, a tenant
            # name, and a numeric field that skips sanitize_node's type
            # dispatch (CRYPTO-2-001).
            "signInIdentifier": "+1 801 555 0147",
            "homeTenantName": "Contoso Ltd",
            "autonomousSystemNumber": 64512,
            "deviceDetail": {
                "displayName": "Alice's iPhone",
                "operatingSystem": "iOS",
                "trustType": "Workplace",
            },
            "location": {
                "city": "Lehi",
                "state": "Utah",
                "countryOrRegion": "US",
                "geoCoordinates": {"altitude": None, "latitude": 40.4242, "longitude": -111.85209},
            },
        }) + "\n")
    (snapshot_dir / "manifest.json").write_text(json.dumps({
        "tenantId": TENANT_GUID, "alias": "golden", "datasets": []
    }))
    return snapshot_dir


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_referential_integrity_same_token_everywhere(snapshot, tmp_path):
    map_path = tmp_path / "data" / "golden" / "pseudo_map.json"
    out = sanitize_snapshot(snapshot, map_path)

    users = _read(out / "users.json")
    caps = _read(out / "conditional_access_policies.json")
    roles = _read(out / "roles.json")
    with gzip.open(out / "signins_interactive.jsonl.gz", "rt", encoding="utf-8") as handle:
        signin = json.loads(handle.readline())

    user_token = users[0]["id"]
    assert user_token != USER_GUID
    assert caps[0]["conditions"]["users"]["excludeUsers"] == [user_token]
    assert roles["roleAssignments"][0]["principalId"] == user_token
    assert signin["userId"] == user_token

    upn_token = users[0]["userPrincipalName"]
    assert upn_token.endswith("@tenant.example")
    assert signin["userPrincipalName"] == upn_token

    name_token = users[0]["displayName"]
    assert name_token.startswith("User ")
    assert signin["userDisplayName"] == name_token


def test_never_transform_list_is_preserved(snapshot, tmp_path):
    out = sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json")
    caps = _read(out / "conditional_access_policies.json")
    roles = _read(out / "roles.json")
    skus = _read(out / "org_licenses.json")["subscribedSkus"]

    users_block = caps[0]["conditions"]["users"]
    assert users_block["includeRoles"] == [ROLE_TEMPLATE]
    apps_block = caps[0]["conditions"]["applications"]
    assert apps_block["excludeApplications"] == [FIRST_PARTY_APP]
    assert apps_block["includeApplications"] == ["All"]
    assert roles["roleDefinitions"][0]["templateId"] == ROLE_TEMPLATE
    assert skus[0]["skuId"] == SKU
    assert skus[0]["servicePlans"][0]["servicePlanId"] == PLAN
    # Policy structure: display name of the policy stays readable.
    assert caps[0]["displayName"] == "CA001 Require MFA for all users"


def test_ips_map_to_documentation_ranges_preserving_distinctness(snapshot, tmp_path):
    out = sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json")
    location = _read(out / "named_locations.json")[0]
    cidrs = [r["cidrAddress"] for r in location["ipRanges"]]
    assert all(c.startswith(("203.0.113.", "198.51.100.")) for c in cidrs)
    assert all(c.endswith("/24") for c in cidrs)
    assert len(set(cidrs)) == 2
    with gzip.open(out / "signins_interactive.jsonl.gz", "rt", encoding="utf-8") as handle:
        signin = json.loads(handle.readline())
    assert signin["ipAddress"].startswith(("203.0.113.", "198.51.100."))


def test_ip_pseudonyms_stay_distinct_across_the_block_boundary(tmp_path):
    """Every real IPv4 must map to its own documentation address: a collision
    would silently merge two real sources into one in the sign-in feed. This
    walks past the first /24 (254 hosts) into the second block and confirms
    254 distinct inputs give 254 distinct outputs, none repeating and none
    hitting .0. The 255th input is the first address of 198.51.100.0/24."""
    from iamai.sanitize import Pseudonymizer

    pseudo = Pseudonymizer(tmp_path / "pseudo_map.json")
    mapped = [pseudo.map_ip(f"10.0.{i // 256}.{i % 256}", 4) for i in range(255)]
    assert len(set(mapped)) == 255
    assert all(not m.endswith(".0") for m in mapped)
    assert mapped[0] == "203.0.113.1"
    assert mapped[253] == "203.0.113.254"
    assert mapped[254] == "198.51.100.1"
    # Stable: asking again returns the same token, does not consume a new one.
    assert pseudo.map_ip("10.0.0.0", 4) == mapped[0]
    # IPv6 uses its own pool and never collides with the IPv4 tokens.
    assert pseudo.map_ip("2606:4700::1111", 6) == "2001:db8::1"
    assert pseudo.map_ip("2606:4700::1111", 6) == "2001:db8::1"


def test_ip_pseudonyms_overflow_past_the_documentation_ranges_without_colliding(tmp_path):
    """A real 30-day sign-in feed routinely holds far more than the 508 hosts in
    the two documentation /24s. Past 508, allocation must continue into the
    non-routable 198.18.0.0/15 benchmarking range, still distinct, never
    raising and never reusing an address already given to a different source.
    (An earlier version raised at 509, which crashed sanitize on any real
    tenant; the heavy-snapshot scale test caught it.)"""
    from iamai.sanitize import Pseudonymizer

    pseudo = Pseudonymizer(tmp_path / "pseudo_map.json")
    mapped = [pseudo.map_ip(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}", 4) for i in range(20000)]
    assert len(set(mapped)) == 20000, "distinct real IPs must map to distinct tokens"
    # First 508 stay in the documentation ranges; the rest land in 198.18.0.0/15.
    assert mapped[507] == "198.51.100.254"
    assert mapped[508].startswith("198.18.")
    assert all(m.startswith(("203.0.113.", "198.51.100.", "198.18.", "198.19.")) for m in mapped)
    # Stable: re-asking returns the same token, does not consume a new slot.
    assert pseudo.map_ip("10.0.0.0", 4) == mapped[0]


def test_verified_domains_become_tenant_example(snapshot, tmp_path):
    out = sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json")
    domains = _read(out / "domains.json")
    ids = {d["id"] for d in domains}
    assert "contoso.com" not in ids
    assert "tenant.example" in ids


def test_mapping_is_stable_across_runs(snapshot, tmp_path):
    map_path = tmp_path / "pseudo_map.json"
    out1 = sanitize_snapshot(snapshot, map_path)
    first = _read(out1 / "users.json")
    out1_bytes = (out1 / "users.json").read_bytes()
    # Re-running with the persisted map produces identical tokens.
    out2 = sanitize_snapshot(snapshot, map_path)
    assert (out2 / "users.json").read_bytes() == out1_bytes
    assert _read(out2 / "users.json")[0]["id"] == first[0]["id"]


def test_manifest_tenant_id_is_pseudonymized(snapshot, tmp_path):
    out = sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json")
    manifest = _read(out / "manifest.json")
    assert manifest["tenantId"] != TENANT_GUID


def test_composite_sku_id_maps_tenant_and_keeps_sku(snapshot, tmp_path):
    out = sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json")
    sku_obj = _read(out / "org_licenses.json")["subscribedSkus"][0]
    tenant_token = _read(out / "manifest.json")["tenantId"]
    assert TENANT_GUID not in sku_obj["id"]
    # Same token as everywhere else, and the universal SKU GUID survives.
    assert sku_obj["id"] == f"{tenant_token}_{SKU}"


def test_first_party_appid_kept_tenant_created_appid_mapped(snapshot, tmp_path):
    out = sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json")
    sps = {sp["displayName"]: sp for sp in _read(out / "service_principals.json")}
    assert sps["Graph Explorer"]["appId"] == MSFT_OWNED_APP
    assert sps["Graph Explorer"]["appOwnerOrganizationId"] == MS_SERVICES_TENANT
    assert sps["IAMAI Collector"]["appId"] != TENANT_OWNED_APP
    assert sps["IAMAI Collector"]["appOwnerOrganizationId"] != TENANT_GUID
    # Stable mapping: the tenant-created appId gets the same token on rerun.
    again = {sp["displayName"]: sp for sp in _read(
        sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json") / "service_principals.json"
    )}
    assert again["IAMAI Collector"]["appId"] == sps["IAMAI Collector"]["appId"]


def test_geo_coordinates_are_nulled_not_passed_through(snapshot, tmp_path):
    """geoCoordinates is a pair of floats, not text, so the type dispatch in
    sanitize_node() passed it through unchanged while the plain-text
    city/state next to it was correctly redacted. A real sign-in's
    coordinates survived this gap into a committed fixture (found by running
    a secret scanner over the full history before publishing)."""
    out = sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json")
    with gzip.open(out / "signins_interactive.jsonl.gz", "rt", encoding="utf-8") as handle:
        signin = json.loads(handle.readline())
    assert signin["location"]["city"] == "redacted"
    assert signin["location"]["state"] == "redacted"
    assert signin["location"]["geoCoordinates"] is None


def test_signin_keeplist_drops_unrecognized_fields(snapshot, tmp_path):
    """The sign-in feed is pulled as the full Graph object, so sanitize_node's
    key-allowlist would pass through any field it does not recognise -- a
    phone number, a tenant name, a bare int. For this feed the sanitizer fails
    safe: only known fields survive, and the four the engine actually reads
    are among them (CRYPTO-2-001)."""
    out = sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json")
    with gzip.open(out / "signins_interactive.jsonl.gz", "rt", encoding="utf-8") as handle:
        signin = json.loads(handle.readline())
    # Dropped: not on the keep-list.
    assert "signInIdentifier" not in signin
    assert "homeTenantName" not in signin
    assert "autonomousSystemNumber" not in signin
    # None of the dropped values survive anywhere in the event.
    blob = json.dumps(signin)
    assert "555 0147" not in blob and "Contoso" not in blob and "64512" not in blob
    # Kept: the fields the grading engine and questionnaire read.
    assert "clientAppUsed" in signin
    assert signin["userPrincipalName"].endswith("@tenant.example")
    assert "userId" in signin and "ipAddress" in signin


def test_device_display_name_is_pseudonymized(snapshot, tmp_path):
    """deviceDetail.displayName defaults to "<Owner's Name>'s <device>" on
    every major OS, so it carries a real person's name on nearly every
    sign-in event. The displayName rule only pseudonymized user, group, and
    organization objects; a device object fell through to "structure, not
    personal data" and was left readable."""
    out = sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json")
    with gzip.open(out / "signins_interactive.jsonl.gz", "rt", encoding="utf-8") as handle:
        signin = json.loads(handle.readline())
    assert signin["deviceDetail"]["displayName"] == "Device 1"
    assert "Alice" not in signin["deviceDetail"]["displayName"]
    # Structural fields on the same object are unaffected.
    assert signin["deviceDetail"]["operatingSystem"] == "iOS"


def test_policy_enablement_state_is_not_treated_as_an_address(snapshot, tmp_path):
    """"state" collides with the key Conditional Access policies and
    authentication method configurations use for their own enablement status,
    an identical key name with an unrelated meaning. Redacting it
    unconditionally silently destroyed whether a policy is even turned on in
    every sanitized snapshot -- confirmed by running the fixed sanitizer over
    a real Conditional Access policy before this fix, which came back with
    every policy's "enabled"/"disabled" replaced by the literal string
    "redacted". Only the address sense (a sibling city/street/postalCode, or
    the organization object itself) should be redacted."""
    out = sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json")
    caps = _read(out / "conditional_access_policies.json")
    assert caps[0]["state"] not in ("redacted", None)


def test_a_us_state_next_to_an_address_field_is_still_redacted(snapshot, tmp_path):
    out = sanitize_snapshot(snapshot, tmp_path / "pseudo_map.json")
    with gzip.open(out / "signins_interactive.jsonl.gz", "rt", encoding="utf-8") as handle:
        signin = json.loads(handle.readline())
    assert signin["location"]["state"] == "redacted"


def test_universal_keys_is_pinned():
    """A GUID seen once under any UNIVERSAL_KEYS key is preserved everywhere in
    the snapshot, so a key whose values are tenant specific would leak them
    through every other field too (BUGS.md item 18). This pins the set: adding
    a key means deliberately updating this test, and the only acceptable
    reason is that its values are Microsoft published constants identical in
    every tenant."""
    from iamai.sanitize import UNIVERSAL_KEYS

    assert set(UNIVERSAL_KEYS) == {
        "roleTemplateId",
        "templateId",
        "includeRoles",
        "excludeRoles",
        "skuId",
        "servicePlanId",
        "skuPartNumber",
        "servicePlanName",
    }
