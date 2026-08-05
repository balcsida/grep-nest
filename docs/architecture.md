# Architecture

```text
GitHub Enterprise -> PostgreSQL <- indexer / scanners
                       |              |
REST and MCP -> server -> graph client -> one LadybugDB runtime
                       |                         |
                      Zoekt                  derived graph files
```

`grepnest-server` is the sole Zoekt search client. It authenticates a single
bearer credential, selects repositories permitted to that principal, converts
those repositories to Zoekt `RepoIDs`, applies bounded search limits, and
normalizes the response. A request that selects no authorized repositories
returns no matches without calling Zoekt.

Browser sign-in may enable OIDC, GitHub OAuth, or both; the provider list is
deterministically OIDC then GitHub. Both use the same Authorization Code + PKCE
flow and store only a hashed opaque GrepNest session. Same-origin browser REST
requests use the HttpOnly session cookie. GitHub OAuth's metadata/flow provider
is `github`, but its identity and session method is `oauth`; its routes are
`/auth/oauth/github/login` and `/auth/oauth/github/callback`.

GitHub OAuth canonicalizes the HTTPS GitHub web origin as issuer and uses the
positive numeric GitHub user ID as subject. It links an active SCIM user only
when `externalId` exactly equals `github:https://github.com:<numeric-id>` on
GitHub.com. This immutable identity survives login or display-name changes.
The access token is used once for the authenticated-user request, never stored
or refreshed; the authorization request sends no scope and rejects a granted
scope. `/mcp` remains bearer-only and rejects browser-session cookies.

When enabled, `/scim/v2` uses a separate secret-file bearer credential and
writes the same PostgreSQL users, groups, and memberships used by browser
providers and authorization. OIDC binds its configured link claim to SCIM
`externalId`; GitHub OAuth uses its canonical `github:<issuer>:<subject>` link.
Sessions and API tokens resolve live directory state on every request, so SCIM
deactivation or deletion takes effect immediately.

REST and MCP call the same search service. `/mcp` is hosted Streamable HTTP
MCP behind bearer authentication. `grepnest-mcp` is a stdio proxy: it connects
to `<GREPNEST_SERVER_URL>/mcp` with `GREPNEST_TOKEN`, lists the hosted tools,
and forwards calls. It does not call Zoekt.

The embedded Web UI at `/` and `/index.html` is a thin, same-origin client of
the repository service at `GET /v1/repositories` and the search service at
`POST /v1/search`. It makes no authorization decisions: repository names are
only usability selectors, and the server authenticates every API request and
enforces the principal's repository scope.

Beginning in Milestone 2, PostgreSQL supplies repository metadata and the
durable index queue. `grepnest-server` verifies GitHub webhooks and reconciles
GitHub App installations. That GitHub App is separate from user OAuth and is
the only credential used for repository work. `grepnest-indexer` leases one
job at a time, fetches
only its default branch, and publishes the indexed SHA after Zoekt confirms
visibility through `/api/list`. Search suppresses a result when Zoekt's branch
version differs from PostgreSQL's committed indexed SHA. Runtime bearer scopes
bind to numeric GitHub repository IDs within an installation boundary; mutable
repository names are selectors only.

The local durable Compose profile keeps PostgreSQL and Zoekt on the internal
network and bind-mounts the host indexer's shard directory into Zoekt. Zoekt is
published only at `127.0.0.1:6070`; it is not public ingress. OpenShift
packaging and production ingress remain Milestone 3 work. See `docs/adr` for
accepted decisions.

## Derived graph analysis

PostgreSQL is authoritative for repository state, indexed default-branch SHA,
graph artifacts, upload metadata, and graph jobs. LadybugDB is a local,
derived query store. It may be discarded and rebuilt from PostgreSQL; it is not
a backup source or an authority for authorization or repository freshness.

The graph runtime has exactly one writable owner. `embedded` (the default)
runs it in the indexer process and stores the database on the node volume.
`separate` runs one `grepnest-graph` owner with its own volume. Scanners are
independent, horizontally scalable workers that write artifacts to PostgreSQL,
not LadybugDB. In both modes every server replica is an authenticated graph
client; it never opens a local LadybugDB copy.

The server resolves an authorized repository selector (numeric GitHub ID or
name) to its current indexed default-branch SHA before a graph query. It
reauthorizes selected and returned repositories against the exact SHA after
the graph response, returning `graph_not_ready` if the snapshot changed. A
requested non-indexed branch returns `branch_not_indexed`. The public surface
is limited to `context`, `impact`, `trace`, and administrator-only read-only
Cypher; request/response schemas, response discriminators, and bounds are in
the [OpenAPI contract](openapi.yaml).

Graph ingestion accepts an external native graph artifact at the exact indexed
SHA. Pre-generated `.scip` upload remains a distinct code-navigation path: it
is not native scanning. When a native graph is unavailable, an exact-SHA SCIP
upload can provide the documented fallback state; it does not turn SCIP into a
native scan. Runtime synchronization and compatibility rebuild read the stored
source artifacts from PostgreSQL.

The graph HTTP listener is an internal bearer-protected hop. Compose keeps it
on the internal network. Helm provides a ClusterIP Service only and renders no
graph Ingress. The server and graph owner share an internal secret: Helm stages
projected secrets while Compose mounts the source file read-only. See
[ADR-0012](adr/0012-derived-ladybug-graph.md) for the storage and topology
decision.
