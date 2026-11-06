# Operations catalog

All listed operations are read-only and route through the same audited MCP/CLI implementation. A tool count describes interface coverage, not live verification.

## Incidents

| MCP tool | Purpose |
|---|---|
| `clouddlp_incidents` | Search bounded DLP incidents. |
| `clouddlp_incident_matches` | Read violating components for an incident. |

## Profiles and detection content

| MCP tool | Purpose |
|---|---|
| `clouddlp_profiles` | List DLP profiles. |
| `clouddlp_profile` | Read a DLP profile. |
| `clouddlp_profile_history` | Read DLP profile history. |
| `clouddlp_custom_groups` | List custom groups. |
| `clouddlp_custom_group` | Read one custom group. |
| `clouddlp_data_identifiers` | List data identifiers. |
| `clouddlp_data_identifier` | Read one data identifier. |
| `clouddlp_validators` | List data identifier validators. |
| `clouddlp_reusable_patterns` | List reusable DLP patterns. |
| `clouddlp_reusable_pattern` | Read a reusable DLP pattern version. |

## Index health

| MCP tool | Purpose |
|---|---|
| `clouddlp_indices` | List DLP index health and versions. |
| `clouddlp_index` | Read DLP index details. |

## Limits and next work

Incident attachments can expose protected content. The public profile/pattern response examples are underspecified, so their raw response shape is marked unverified. Index upload and profile changes require live result and rollback proof.

API paths and response examples are from the official Broadcom documentation listed below. No tenant or appliance has been supplied for live verification; consult [VERIFICATION.md](VERIFICATION.md).

- [clouddlp_auth](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/clouddlp_auth.md)
- [casb_incidents](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/casb_incidents%20.md)
- [casb_profiles](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/casb_profiles%20.md)
- [casb_custom_groups](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/casb_custom_groups%20.md)
- [casb_data_identifiers](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/casb_data_identifiers%20.md)
- [casb_resusable_patterns](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/casb_resusable_patterns%20.md)
- [casb_index_mgmt](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/casb_index_mgmt.md)
