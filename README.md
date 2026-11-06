<!-- mcp-name: io.github.AIops-tools/symantec-clouddlp-aiops -->

# Symantec Cloud DLP AIops

Independent audited MCP server, CLI and skill for CloudSOC DLP incidents, profiles, detection patterns, data identifiers and index health. This initial release exposes 14 read-only tools. MCP and CLI call the same governed functions; API credentials remain in environment variables, TLS verification is on, and every call records a local audit event.

> Community-maintained project. Not affiliated with or endorsed by Broadcom or Symantec; product names are their owners’ trademarks.

## Configure

```sh
export SYMANTEC_CLOUDDLP_URL="..."
export SYMANTEC_CLOUDDLP_KEY_ID="..."
export SYMANTEC_CLOUDDLP_KEY_SECRET="..."
export SYMANTEC_CLOUDDLP_TENANT="..."
```

`SYMANTEC_CLOUDDLP_URL` must be the CloudSOC HTTPS origin (`https://app.elastica.net` or `https://app.eu.elastica.net`), without a path. Optional `SYMANTEC_CLOUDDLP_CA_BUNDLE` points to a trusted CA bundle; `SYMANTEC_CLOUDDLP_TIMEOUT` defaults to 30 seconds. Audit state defaults to `~/.symantec-clouddlp-aiops/` and can be relocated with `SYMANTEC_CLOUDDLP_AIOPS_HOME`.

See the [operations catalog](docs/OPERATIONS.md) for the complete tool list, scope and deferred operations.

## Use

```sh
uvx --from symantec-clouddlp-aiops==0.1.0 symantec-clouddlp-aiops profiles
uvx --from symantec-clouddlp-aiops==0.1.0 symantec-clouddlp-aiops-mcp
```

Search incidents in a bounded time window and follow the search-after cursor. Profile API response schemas are weakly specified, so raw response shape is surfaced explicitly. See [verification](docs/VERIFICATION.md) for the exact evidence and unverified live behavior. No state-changing operations are exposed.
