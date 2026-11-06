# Verification

## Official API contracts reviewed

- [clouddlp_auth](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/clouddlp_auth.md)
- [casb_incidents](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/casb_incidents.md)
- [casb_profiles](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/casb_profiles.md)
- [casb_custom_groups](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/casb_custom_groups.md)
- [casb_data_identifiers](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/casb_data_identifiers.md)

The auth scheme, listed paths, query bounds and response examples informed the read-only implementation. An official schema example is not a substitute for a live response.

## Local validation

- Contract-shaped HTTP mock tests and inherited governance tests passed (40 pytest tests). Ruff passed; Bandit found 0 Medium+ issues. The 0.1.0 wheel installed in an external virtual environment and its MCP server imported from site-packages. All five handbook gates passed over 36 tools.
- The vendored governance harness uses the same path for MCP and CLI. Query-only POST routes are explicitly allowlisted.

## Not yet verified

- No live Symantec Cloud DLP tenant/appliance or test credentials have been supplied. Authentication, privileges, response shape, pagination and real operational behavior remain unverified against a server.
- No write or undo workflow is exposed. Any write additions require live result, audit and rollback proof before release.

Cloud DLP incident responses include a `searchAfterValue`, but the official example does not prove that its presence means another page exists. The tool exposes the cursor and reports `truncated: null` / `completionKnown: false` until live behavior establishes end-of-results semantics.

## Expanded coverage review

The [operations catalog](OPERATIONS.md) lists every implemented tool, source API topic and excluded operation. New read paths have contract-shaped HTTP tests. Public API examples may differ from a real tenant; all added paths remain live-unverified.

Successful login and resource responses are read as a stream with a 16 MiB decoded-body limit. The client closes the stream and raises an explicit error as soon as the limit is exceeded, before JSON parsing. Local mock-stream regression tests verify that unread chunks are not consumed, including during login. This does not replace server-side pagination; unpaged endpoints report measured output truncation.
