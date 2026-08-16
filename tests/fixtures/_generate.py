"""One-off generator for the sanitized fixture set.

Fixtures are synthetic snapshots shaped exactly like the documented v1.0/beta
response bodies on Microsoft Learn, populated only with example values
(tenant.example, documentation IP ranges, placeholder GUIDs). Re-run this
file to regenerate them: python tests/fixtures/_generate.py
"""

import json
from pathlib import Path

HERE = Path(__file__).parent

TENANT = "11111111-1111-1111-1111-111111111111"
USER_1 = "20000000-0000-0000-0000-000000000001"
USER_2 = "20000000-0000-0000-0000-000000000002"
USER_BG = "20000000-0000-0000-0000-00000000000b"  # break-glass candidate
GROUP_EXCLUDED = "30000000-0000-0000-0000-000000000001"
POLICY_1 = "40000000-0000-0000-0000-000000000001"
POLICY_2 = "40000000-0000-0000-0000-000000000002"
LOCATION_1 = "50000000-0000-0000-0000-000000000001"
STRENGTH_MFA = "00000000-0000-0000-0000-000000000002"  # built-in MFA strength
ROLE_GA_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
SKU_E5 = "06ebc4ee-1bb5-47dd-8120-11324bc54e06"
PLAN_P2 = "eec0eb4f-6444-4f95-aba0-50c24d67f998"
APP_EXO = "00000002-0000-0ff1-ce00-000000000000"  # Office 365 Exchange Online

fixtures = {}

fixtures["cap_policies.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies",
    "value": [
        {
            "id": POLICY_1,
            "displayName": "CA001 Require MFA for all users",
            "createdDateTime": "2025-01-10T03:00:00Z",
            "modifiedDateTime": "2025-04-01T05:00:00Z",
            "state": "enabled",
            "conditions": {
                "clientAppTypes": ["all"],
                "applications": {
                    "includeApplications": ["All"],
                    "excludeApplications": [],
                    "includeUserActions": [],
                },
                "users": {
                    "includeUsers": ["All"],
                    "excludeUsers": [USER_BG],
                    "includeGroups": [],
                    "excludeGroups": [GROUP_EXCLUDED],
                    "includeRoles": [],
                    "excludeRoles": [],
                },
                "locations": None,
                "platforms": None,
                "signInRiskLevels": [],
                "userRiskLevels": [],
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["mfa"],
                "customAuthenticationFactors": [],
                "termsOfUse": [],
                "authenticationStrength": None,
            },
            "sessionControls": None,
        },
        {
            "id": POLICY_2,
            "displayName": "CA002 Block legacy authentication",
            "createdDateTime": "2025-01-10T03:05:00Z",
            "modifiedDateTime": "2025-01-10T03:05:00Z",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "clientAppTypes": ["exchangeActiveSync", "other"],
                "applications": {
                    "includeApplications": ["All"],
                    "excludeApplications": [],
                    "includeUserActions": [],
                },
                "users": {
                    "includeUsers": ["All"],
                    "excludeUsers": [USER_BG],
                    "includeGroups": [],
                    "excludeGroups": [],
                    "includeRoles": [],
                    "excludeRoles": [],
                },
                "locations": None,
                "platforms": None,
                "signInRiskLevels": [],
                "userRiskLevels": [],
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["block"],
                "customAuthenticationFactors": [],
                "termsOfUse": [],
                "authenticationStrength": None,
            },
            "sessionControls": None,
        },
    ],
}

fixtures["named_locations.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/namedLocations",
    "value": [
        {
            "@odata.type": "#microsoft.graph.ipNamedLocation",
            "id": LOCATION_1,
            "displayName": "Head office",
            "createdDateTime": "2025-01-09T00:00:00Z",
            "modifiedDateTime": "2025-01-09T00:00:00Z",
            "isTrusted": True,
            "ipRanges": [
                {"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "203.0.113.0/24"}
            ],
        },
        {
            "@odata.type": "#microsoft.graph.countryNamedLocation",
            "id": "50000000-0000-0000-0000-000000000002",
            "displayName": "Allowed countries",
            "createdDateTime": "2025-01-09T00:01:00Z",
            "modifiedDateTime": "2025-01-09T00:01:00Z",
            "countriesAndRegions": ["AU", "NZ"],
            "includeUnknownCountriesAndRegions": False,
            "countryLookupMethod": "clientIpAddress",
        },
    ],
}

fixtures["auth_strengths.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationStrengthPolicies",
    "value": [
        {
            "id": STRENGTH_MFA,
            "createdDateTime": "2021-12-01T00:00:00Z",
            "modifiedDateTime": "2021-12-01T00:00:00Z",
            "displayName": "Multifactor authentication",
            "description": "Combinations of methods that satisfy strong authentication, such as a password + SMS",
            "policyType": "builtIn",
            "requirementsSatisfied": "mfa",
            "allowedCombinations": [
                "windowsHelloForBusiness",
                "fido2",
                "x509CertificateMultiFactor",
                "deviceBasedPush",
                "temporaryAccessPassOneTime",
                "temporaryAccessPassMultiUse",
                "password, microsoftAuthenticatorPush",
                "password, softwareOath",
                "password, hardwareOath",
                "password, sms",
                "password, voice",
                "federatedMultiFactor",
                "microsoftAuthenticatorPush, federatedSingleFactor",
                "x509CertificateSingleFactor, federatedSingleFactor",
            ],
        }
    ],
}

fixtures["auth_methods_policy.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#authenticationMethodsPolicy",
    "id": "authenticationMethodsPolicy",
    "displayName": "Authentication Methods Policy",
    "description": "The tenant-wide policy that controls which authentication methods are allowed in the tenant, authentication method registration requirements, and self-service password reset settings",
    "lastModifiedDateTime": "2025-03-01T00:00:00Z",
    "policyVersion": "1.5",
    "policyMigrationState": "migrationComplete",
    "registrationEnforcement": {
        "authenticationMethodsRegistrationCampaign": {
            "snoozeDurationInDays": 1,
            "enforceRegistrationAfterAllowedSnoozes": True,
            "state": "enabled",
            "excludeTargets": [],
            "includeTargets": [
                {
                    "id": "all_users",
                    "targetType": "group",
                    "targetedAuthenticationMethod": "microsoftAuthenticator",
                }
            ],
        }
    },
    "authenticationMethodConfigurations": [
        {
            "@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration",
            "id": "MicrosoftAuthenticator",
            "state": "enabled",
            "isSoftwareOathEnabled": False,
            "excludeTargets": [],
            "featureSettings": {
                "displayAppInformationRequiredState": {
                    "state": "enabled",
                    "includeTarget": {"targetType": "group", "id": "all_users"},
                    "excludeTarget": {"targetType": "group", "id": "00000000-0000-0000-0000-000000000000"},
                },
                "displayLocationInformationRequiredState": {
                    "state": "enabled",
                    "includeTarget": {"targetType": "group", "id": "all_users"},
                    "excludeTarget": {"targetType": "group", "id": "00000000-0000-0000-0000-000000000000"},
                },
            },
            "includeTargets": [
                {"targetType": "group", "id": "all_users", "isRegistrationRequired": False, "authenticationMode": "any"}
            ],
        },
        {
            "@odata.type": "#microsoft.graph.smsAuthenticationMethodConfiguration",
            "id": "Sms",
            "state": "disabled",
            "excludeTargets": [],
            "includeTargets": [
                {"targetType": "group", "id": "all_users", "isRegistrationRequired": False, "isUsableForSignIn": False}
            ],
        },
        {
            "@odata.type": "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration",
            "id": "TemporaryAccessPass",
            "state": "enabled",
            "defaultLifetimeInMinutes": 60,
            "defaultLength": 8,
            "minimumLifetimeInMinutes": 60,
            "maximumLifetimeInMinutes": 480,
            "isUsableOnce": True,
            "excludeTargets": [],
            "includeTargets": [
                {"targetType": "group", "id": GROUP_EXCLUDED, "isRegistrationRequired": False}
            ],
        },
    ],
}

fixtures["security_defaults.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/identitySecurityDefaultsEnforcementPolicy/$entity",
    "id": "00000000-0000-0000-0000-000000000005",
    "displayName": "Security Defaults",
    "description": "Security defaults is a set of basic identity security mechanisms recommended by Microsoft.",
    "isEnabled": False,
}

fixtures["authorization_policy.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authorizationPolicy/$entity",
    "id": "authorizationPolicy",
    "allowInvitesFrom": "adminsAndGuestInviters",
    "allowedToSignUpEmailBasedSubscriptions": True,
    "allowedToUseSSPR": True,
    "allowEmailVerifiedUsersToJoinOrganization": False,
    "allowUserConsentForRiskyApps": False,
    "blockMsolPowerShell": False,
    "description": "Used to manage authorization related settings across the company.",
    "displayName": "Authorization Policy",
    "guestUserRoleId": "2af84b1e-32c8-42b7-82bc-daa82404023b",
    "defaultUserRolePermissions": {
        "allowedToCreateApps": False,
        "allowedToCreateSecurityGroups": False,
        "allowedToCreateTenants": False,
        "allowedToReadBitlockerKeysForOwnedDevice": True,
        "allowedToReadOtherUsers": True,
        "permissionGrantPoliciesAssigned": [],
    },
}

fixtures["users_page1.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
    "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=page2token",
    "value": [
        {
            "id": USER_1,
            "accountEnabled": True,
            "userType": "Member",
            "userPrincipalName": "user1@tenant.example",
            "displayName": "User 1",
            "onPremisesSyncEnabled": None,
            "signInActivity": {
                "lastSignInDateTime": "2026-06-01T01:00:00Z",
                "lastSignInRequestId": "60000000-0000-0000-0000-000000000001",
                "lastNonInteractiveSignInDateTime": "2026-06-09T01:00:00Z",
                "lastNonInteractiveSignInRequestId": "60000000-0000-0000-0000-000000000002",
            },
        },
        {
            "id": USER_2,
            "accountEnabled": True,
            "userType": "Member",
            "userPrincipalName": "user2@tenant.example",
            "displayName": "User 2",
            "onPremisesSyncEnabled": None,
            "signInActivity": {
                "lastSignInDateTime": "2026-05-20T07:00:00Z",
                "lastSignInRequestId": "60000000-0000-0000-0000-000000000003",
            },
        },
    ],
}

fixtures["users_page2.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
    "value": [
        {
            "id": USER_BG,
            "accountEnabled": True,
            "userType": "Member",
            "userPrincipalName": "user3@tenant.example",
            "displayName": "User 3",
            "onPremisesSyncEnabled": None,
            "signInActivity": None,
        }
    ],
}

fixtures["registration_details.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#reports/authenticationMethods/userRegistrationDetails",
    "value": [
        {
            "id": USER_1,
            "userPrincipalName": "user1@tenant.example",
            "userDisplayName": "User 1",
            "userType": "member",
            "isAdmin": True,
            "isSsprRegistered": True,
            "isSsprEnabled": True,
            "isSsprCapable": True,
            "isMfaRegistered": True,
            "isMfaCapable": True,
            "isPasswordlessCapable": False,
            "lastUpdatedDateTime": "2026-06-09T10:00:00Z",
            "methodsRegistered": ["microsoftAuthenticatorPush", "softwareOneTimePasscode"],
            "isSystemPreferredAuthenticationMethodEnabled": True,
            "systemPreferredAuthenticationMethods": ["PhoneAppNotification"],
            "userPreferredMethodForSecondaryAuthentication": "push",
        },
        {
            "id": USER_2,
            "userPrincipalName": "user2@tenant.example",
            "userDisplayName": "User 2",
            "userType": "member",
            "isAdmin": False,
            "isSsprRegistered": False,
            "isSsprEnabled": False,
            "isSsprCapable": False,
            "isMfaRegistered": False,
            "isMfaCapable": False,
            "isPasswordlessCapable": False,
            "lastUpdatedDateTime": "2026-06-09T10:00:00Z",
            "methodsRegistered": [],
            "isSystemPreferredAuthenticationMethodEnabled": True,
            "systemPreferredAuthenticationMethods": [],
            "userPreferredMethodForSecondaryAuthentication": "none",
        },
    ],
}

fixtures["role_definitions.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#roleManagement/directory/roleDefinitions",
    "value": [
        {
            "id": ROLE_GA_TEMPLATE,
            "description": "Can manage all aspects of Microsoft Entra ID and Microsoft services that use Microsoft Entra identities.",
            "displayName": "Global Administrator",
            "isBuiltIn": True,
            "isEnabled": True,
            "templateId": ROLE_GA_TEMPLATE,
            "version": "1",
            "rolePermissions": [
                {"allowedResourceActions": ["microsoft.directory/applications/allProperties/allTasks"], "condition": None}
            ],
        }
    ],
}

fixtures["role_assignments.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#roleManagement/directory/roleAssignments",
    "value": [
        {
            "id": "70000000-0000-0000-0000-000000000001",
            "roleDefinitionId": ROLE_GA_TEMPLATE,
            "principalId": USER_1,
            "directoryScopeId": "/",
        }
    ],
}

fixtures["role_eligibility.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#roleManagement/directory/roleEligibilitySchedules",
    "value": [
        {
            "id": "80000000-0000-0000-0000-000000000001",
            "principalId": USER_2,
            "roleDefinitionId": ROLE_GA_TEMPLATE,
            "directoryScopeId": "/",
            "appScopeId": None,
            "createdDateTime": "2025-06-01T00:00:00Z",
            "modifiedDateTime": "2025-06-01T00:00:00Z",
            "status": "Provisioned",
            "memberType": "Direct",
            "scheduleInfo": {
                "startDateTime": "2025-06-01T00:00:00Z",
                "expiration": {"type": "noExpiration"},
            },
        }
    ],
}

fixtures["groups.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#groups",
    "value": [
        {
            "id": GROUP_EXCLUDED,
            "displayName": "Group 1",
            "groupTypes": [],
            "securityEnabled": True,
            "onPremisesSyncEnabled": None,
            "membershipRule": None,
        },
        {
            "id": "30000000-0000-0000-0000-000000000002",
            "displayName": "Group 2",
            "groupTypes": ["Unified"],
            "securityEnabled": False,
            "onPremisesSyncEnabled": None,
            "membershipRule": None,
        },
    ],
}

fixtures["service_principals.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#servicePrincipals(id,appId,displayName,accountEnabled)",
    "value": [
        {
            "id": "90000000-0000-0000-0000-000000000001",
            "appId": APP_EXO,
            "displayName": "Office 365 Exchange Online",
            "accountEnabled": True,
        },
        {
            "id": "90000000-0000-0000-0000-000000000002",
            "appId": "a0000000-0000-0000-0000-00000000000a",
            "displayName": "Line of business app",
            "accountEnabled": True,
        },
    ],
}

fixtures["organization.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#organization",
    "value": [
        {
            "id": TENANT,
            "displayName": "Tenant",
            "countryLetterCode": "AU",
            "tenantType": "AAD",
            "onPremisesSyncEnabled": None,
            "verifiedDomains": [
                {
                    "capabilities": "Email, OfficeCommunicationsOnline",
                    "isDefault": True,
                    "isInitial": False,
                    "name": "tenant.example",
                    "type": "Managed",
                },
                {
                    "capabilities": "Email, OfficeCommunicationsOnline",
                    "isDefault": False,
                    "isInitial": True,
                    "name": "tenant2.example",
                    "type": "Managed",
                },
            ],
        }
    ],
}

fixtures["subscribed_skus.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#subscribedSkus",
    "value": [
        {
            "id": f"{TENANT}_{SKU_E5}",
            "accountId": TENANT,
            "accountName": "tenant",
            "appliesTo": "User",
            "capabilityStatus": "Enabled",
            "consumedUnits": 3,
            "prepaidUnits": {"enabled": 5, "suspended": 0, "warning": 0, "lockedOut": 0},
            "skuId": SKU_E5,
            "skuPartNumber": "ENTERPRISEPREMIUM",
            "servicePlans": [
                {
                    "servicePlanId": PLAN_P2,
                    "servicePlanName": "AAD_PREMIUM_P2",
                    "provisioningStatus": "Success",
                    "appliesTo": "User",
                }
            ],
        }
    ],
}

fixtures["domains.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#domains",
    "value": [
        {
            "id": "tenant.example",
            "authenticationType": "Managed",
            "isAdminManaged": True,
            "isDefault": True,
            "isInitial": False,
            "isRoot": True,
            "isVerified": True,
            "supportedServices": ["Email", "OfficeCommunicationsOnline"],
        },
        {
            "id": "tenant2.example",
            "authenticationType": "Managed",
            "isAdminManaged": True,
            "isDefault": False,
            "isInitial": True,
            "isRoot": True,
            "isVerified": True,
            "supportedServices": ["Email", "OfficeCommunicationsOnline"],
        },
    ],
}

fixtures["signins_interactive.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns",
    "value": [
        {
            "id": "60000000-0000-0000-0000-000000000001",
            "createdDateTime": "2026-06-01T01:00:00Z",
            "userDisplayName": "User 1",
            "userPrincipalName": "user1@tenant.example",
            "userId": USER_1,
            "appId": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
            "appDisplayName": "Graph explorer",
            "ipAddress": "203.0.113.5",
            "clientAppUsed": "Browser",
            "correlationId": "b0000000-0000-0000-0000-000000000001",
            "conditionalAccessStatus": "success",
            "isInteractive": True,
            "riskDetail": "none",
            "riskLevelAggregated": "none",
            "riskLevelDuringSignIn": "none",
            "riskState": "none",
            "riskEventTypes": [],
            "resourceDisplayName": "Microsoft Graph",
            "resourceId": "00000003-0000-0000-c000-000000000000",
            "status": {"errorCode": 0, "failureReason": None, "additionalDetails": None},
            "deviceDetail": {
                "deviceId": "",
                "displayName": None,
                "operatingSystem": "Windows 11",
                "browser": "Edge 137.0.0",
                "isCompliant": None,
                "isManaged": None,
                "trustType": None,
            },
            "location": {
                "city": "Sydney",
                "state": "New South Wales",
                "countryOrRegion": "AU",
                "geoCoordinates": {"altitude": None, "latitude": -33.8, "longitude": 151.2},
            },
            "appliedConditionalAccessPolicies": [
                {
                    "id": POLICY_1,
                    "displayName": "CA001 Require MFA for all users",
                    "enforcedGrantControls": ["Mfa"],
                    "enforcedSessionControls": [],
                    "result": "success",
                },
                {
                    "id": POLICY_2,
                    "displayName": "CA002 Block legacy authentication",
                    "enforcedGrantControls": [],
                    "enforcedSessionControls": [],
                    "result": "reportOnlyNotApplied",
                },
            ],
        },
        {
            "id": "60000000-0000-0000-0000-000000000003",
            "createdDateTime": "2026-05-20T07:00:00Z",
            "userDisplayName": "User 2",
            "userPrincipalName": "user2@tenant.example",
            "userId": USER_2,
            "appId": "00000002-0000-0ff1-ce00-000000000000",
            "appDisplayName": "Office 365 Exchange Online",
            "ipAddress": "198.51.100.7",
            "clientAppUsed": "Exchange ActiveSync",
            "correlationId": "b0000000-0000-0000-0000-000000000002",
            "conditionalAccessStatus": "reportOnly",
            "isInteractive": True,
            "riskDetail": "none",
            "riskLevelAggregated": "none",
            "riskLevelDuringSignIn": "none",
            "riskState": "none",
            "riskEventTypes": [],
            "resourceDisplayName": "Office 365 Exchange Online",
            "resourceId": "00000002-0000-0ff1-ce00-000000000000",
            "status": {"errorCode": 0, "failureReason": None, "additionalDetails": None},
            "deviceDetail": {
                "deviceId": "",
                "displayName": None,
                "operatingSystem": "Android",
                "browser": "",
                "isCompliant": None,
                "isManaged": None,
                "trustType": None,
            },
            "location": {
                "city": "Sydney",
                "state": "New South Wales",
                "countryOrRegion": "AU",
                "geoCoordinates": {"altitude": None, "latitude": -33.8, "longitude": 151.2},
            },
            "appliedConditionalAccessPolicies": [
                {
                    "id": POLICY_2,
                    "displayName": "CA002 Block legacy authentication",
                    "enforcedGrantControls": ["Block"],
                    "enforcedSessionControls": [],
                    "result": "reportOnlyFailure",
                }
            ],
        },
    ],
}

fixtures["signins_noninteractive.json"] = {
    "@odata.context": "https://graph.microsoft.com/beta/$metadata#auditLogs/signIns",
    "value": [
        {
            "id": "60000000-0000-0000-0000-000000000002",
            "createdDateTime": "2026-06-09T01:00:00Z",
            "userDisplayName": "User 1",
            "userPrincipalName": "user1@tenant.example",
            "userId": USER_1,
            "appId": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
            "appDisplayName": "Graph explorer",
            "ipAddress": "203.0.113.5",
            "clientAppUsed": "Mobile Apps and Desktop clients",
            "correlationId": "b0000000-0000-0000-0000-000000000003",
            "conditionalAccessStatus": "notApplied",
            "isInteractive": False,
            "signInEventTypes": ["nonInteractiveUser"],
            "resourceDisplayName": "Microsoft Graph",
            "resourceId": "00000003-0000-0000-c000-000000000000",
            "status": {"errorCode": 0, "failureReason": None, "additionalDetails": None},
            "appliedConditionalAccessPolicies": [],
            "sessionLifetimePolicies": [],
        }
    ],
}

fixtures["risky_users.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identityProtection/riskyUsers",
    "value": [
        {
            "id": USER_2,
            "isDeleted": False,
            "isProcessing": False,
            "riskLastUpdatedDateTime": "2026-06-05T00:00:00Z",
            "riskLevel": "medium",
            "riskState": "atRisk",
            "riskDetail": "none",
            "userDisplayName": "User 2",
            "userPrincipalName": "user2@tenant.example",
        }
    ],
}

fixtures["auth_methods_user.json"] = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users('" + USER_1 + "')/authentication/methods",
    "value": [
        {
            "@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
            "id": "c0000000-0000-0000-0000-000000000001",
            "displayName": "Pixel 9",
            "deviceTag": "SoftwareTokenActivated",
            "phoneAppVersion": "6.2506.0",
            "createdDateTime": "2025-06-01T00:00:00Z",
        }
    ],
}

for name, payload in fixtures.items():
    (HERE / name).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
print(f"wrote {len(fixtures)} fixtures")
