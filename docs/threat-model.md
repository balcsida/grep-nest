# Threat Model

## Protected assets

- source, repository metadata, and indexed revisions;
- bearer tokens and GitHub App installation credentials;
- authorization scopes and server-selected Zoekt repository IDs;
- service and index availability.
- OIDC and GitHub OAuth login transactions and browser sessions.
- the dedicated SCIM provisioning token and directory mutations.
- local recovery credentials, shared login throttles, sessions, and immutable
  security audit events.

## SSO and break-glass recovery

OIDC is the primary browser authentication path. Local administrator recovery
is disabled by default and requires two independent operator actions: offline
password provisioning through `grepnest-admin` standard input or a terminal,
then deliberate route enablement in deployment configuration. Passwords,
hashes, salts, session tokens, request bodies, and OIDC claims are absent from
deployment values and audit records. An unavailable or failing IdP never
enables the local route.

The first recovery authentication is rotation-only. Successful rotation
replaces the password, clears the forced-rotation state, revokes existing
sessions and API tokens, and issues a new opaque session. PostgreSQL stores
credentials, attempt throttles, and sessions, so limits and revocation apply
across replicas. The sixth attempt in the fixed fifteen-minute window is
blocked with a bounded `Retry-After`.

Recovery ends by restoring and verifying an external provider (OIDC or GitHub
OAuth), replacing or suspending the
local account and revoking its credentials, disabling the route, applying the
deployment, and checking every replica. Configuration is loaded at process
startup; partial rollouts can expose different route availability until all
replicas restart.

## Milestones 0-1 controls

- `/v1/search` and `/mcp` require exactly one bearer credential; malformed,
  missing, duplicate, or unknown credentials receive a generic 401 response;
- static tokens are compared in constant time and must be distinct at startup;
- the server intersects requested repository names with the authenticated
  principal's scope, then sends only the resulting Zoekt `RepoIDs`;
- Zoekt is internal to the application; Compose publishes it only on loopback;
- JSON bodies, result counts, context, timeout, backend response, and outbound
  response all have server-side bounds;
- errors are generic and structured; token values and Authorization headers are
  not logged;
- fixture indexing uses pinned binaries with argument arrays and never runs
  fixture repository code.

## Browser OAuth controls

- GitHub OAuth uses a dedicated per-environment OAuth App, separate from the
  GitHub App repository credential; its callback is fixed at
  `/auth/oauth/github/callback` under the HTTPS public origin;
- state and browser binding are independent 32-byte random values stored only
  as hashes; provider-bound, one-time flows reject expiry, replay, duplicate
  callback values, and cross-provider confusion;
- PKCE S256 binds authorization codes to the initiating browser; GitHub OAuth
  asks for no scope and rejects every non-empty granted scope;
- the canonical HTTPS issuer plus positive numeric GitHub subject form the
  SCIM link `github:https://github.com:<numeric-id>`, avoiding mutable login
  and rename binding; only active SCIM users may bind or retain access;
- exchanged access tokens are held only in callback-local memory for one
  bounded authenticated-user request, never logged, audited, returned,
  persisted, refreshed, or supplied to the GitHub App;
- OAuth uses the configured GitHub origins, existing custom CA, bounded
  transport, and redirect policy, preventing cross-origin credential leakage;
  GHES OAuth is unverified; and
- REST rejects mixed bearer/session credentials, while MCP remains bearer-only
  and rejects browser-session cookies.

## Milestone 2 controls

- webhook HMAC is checked over bounded untouched bytes before JSON decoding;
- App and installation credentials stay in memory and are redacted from logs;
- Go and Git extend system trust with the same custom CA, require HTTPS, and
  reject redirects and unconfigured hosts;
- persisted Git remotes contain no credentials, and child processes receive an
  allowlisted environment through a fixed askpass helper;
- indexing never runs repository hooks, code, submodules, LFS smudge filters,
  build tools, or repository-supplied ctags configuration;
- numeric IDs determine database and disk identity; untrusted names and paths
  never determine filesystem locations;
- bearer authorization binds to explicit numeric GitHub repository-ID subsets,
  excludes disabled state before selecting RepoIDs, and never treats a mutable
  name as identity;
- PostgreSQL transactions deduplicate deliveries and coalesce pushes, leases
  prevent concurrent indexing, and indexed SHA is published only after exact
  Zoekt visibility;
- search suppresses Zoekt revisions that do not match committed repository
  metadata, and file reads authorize before fetching the committed indexed SHA;
- HTTP bodies, decoded files, child output, command duration, and free-space
  admission are bounded.

## Web UI controls

- the bearer token is held only in session storage or memory and is cleared on
  authentication failure;
- a strict hash-based CSP permits only same-origin connections and the exact
  embedded style and script blocks;
- API-controlled text is rendered through DOM text nodes, never HTML sinks;
- outbound repository links require HTTPS, encode SHA and path components, and
  use opener isolation; and
- the client selects repository names for usability, while the server still
  intersects them with the authenticated principal's numeric authorization
  scope.

## Known limits

SCIM is optional, durable-only, and isolated at `/scim/v2` behind a dedicated
bearer token loaded from a regular secret file. That token cannot authenticate
to REST, MCP, account, or admin APIs and is never accepted as a plaintext
setting. Bounded URLs, queries, bodies, pagination, and PATCH operation counts
limit work. Transactional writes validate members and read-only fields,
preserve the final effective administrator, and make committed deprovisioning
effective for sessions and API tokens on their next request.

OIDC session cookies can be replayed until logout or expiry, and database write
access can forge a chosen session hash. HttpOnly cookies, exact Origin checks,
bounded TTLs, and server-side revocation limit but do not eliminate that risk.
The SCIM token remains valid until every server replica restarts after secret
replacement; protect the public endpoint with HTTPS and restrict token
distribution.

Audit events contain bounded actor/target identifiers, authentication method,
operation, outcome, request ID, and timestamp. The admin API returns a bounded
newest-first page with truncation. Events are append-only, but this release has
no automatic retention or export policy; PostgreSQL growth, backup retention,
and external archival remain operator responsibilities.

This remains a local development slice, not a production security boundary.
Git pack expansion and Zoekt shards require container and volume quotas.
Container isolation, network policy, secret delivery, backup/restore, and
production ingress remain Milestone 3 work. Do not claim production readiness
from local or Compose success. The Helm Ingress is structural support, not
proof of a production ingress deployment.
