# GitHub OAuth Browser Authentication Design

## Scope

GrepNest will add GitHub OAuth Apps as an optional browser identity provider.
Deployments may enable OIDC, GitHub OAuth, both providers, or neither. Existing
bearer authentication remains available in every configuration, local
break-glass remains available when at least one external browser provider is
enabled, and MCP remains bearer-only.

The first manually verified target is GitHub.com. The implementation reuses
GrepNest's configured GitHub web/API origins, custom CA, headers, and transport
policy so the structure also fits GitHub Enterprise Server, but GHES support is
not claimed until it is tested against a supported GHES release.

## Existing Boundaries to Preserve

- REST accepts bearer or browser-session authentication and rejects requests
  carrying both.
- MCP accepts bearer credentials only.
- PostgreSQL stores one-time login flows and opaque session-token hashes so
  login and callback may reach different replicas.
- Every authenticated request resolves current user state, role, and grants;
  sessions do not cache authorization.
- Federated identities bind only to active SCIM users by exact `externalId`.
- The GitHub App remains the only credential used for repository discovery,
  indexing, file access, and reconciliation.
- The embedded web UI renders the generic provider list without
  provider-specific JavaScript or external assets.

## Architecture

### Shared Browser Flow

The security-sensitive HTTP controller currently embedded in the OIDC provider
moves to `internal/sso/browserflow`. It owns state and browser-binding
generation and hashing, nonce and PKCE generation, PostgreSQL flow creation and
consumption, strict callback parameter and cookie parsing, login and callback
auditing, session creation, private response headers, fixed redirects, and
GET-only routes.

The controller receives a compile-time provider specification containing its
metadata, routes, login-flow provider, expected identity provider, cookie name,
authentication method, and audit operations. None of these values comes from
end-user configuration.

A small client interface supplies only two provider-specific operations:

```go
type Client interface {
	AuthorizationURL(state, nonce, verifier string) string
	Exchange(ctx context.Context, code, verifier, expectedNonce string) (authn.Identity, error)
}
```

The controller validates the returned identity and its expected provider
before creating a session. OIDC continues to generate and verify nonce. The
GitHub adapter ignores nonce but shares the same stored flow representation.

### Provider Adapters

The existing OIDC client remains responsible for discovery and ID-token
verification. Its provider becomes a thin constructor around the shared
controller, preserving `/auth/oidc/login`, `/auth/oidc/callback`, the existing
login cookie, audit vocabulary, and session method.

`internal/sso/githuboauth` uses the installed `golang.org/x/oauth2` package for
authorization-code exchange. Its fixed public contract is:

- metadata ID and flow provider: `github`;
- identity provider and session method: `oauth`;
- login route: `/auth/oauth/github/login`;
- callback route: `/auth/oauth/github/callback`;
- login cookie: `__Host-grepnest_oauth_github_login`;
- label: `Sign in with GitHub`.

Authorization and token endpoints are derived from the validated GitHub web
origin. The authenticated-user endpoint is derived from the validated GitHub
API origin. The callback is derived only from `GREPNEST_PUBLIC_URL`.

### Identity and Session Persistence

OIDC-specific persistence method names become provider-neutral federated
identity methods without changing their behavior. Identity lookup still uses
immutable `(issuer, subject)`, first-time binding still requires an active SCIM
user whose `externalId` exactly equals `Identity.LinkID`, and binding plus
session and success-audit creation remains one PostgreSQL transaction.

Migration 016 widens only the existing provider constraints:

- login flows: `oidc`, `github`;
- sessions: `oidc`, `oauth`, `local`.

No token, identity, user, role, grant, or session schema is otherwise changed.

## GitHub Identity and Token Handling

After exchange, the callback uses the access token once to call GitHub's
authenticated-user API. The response maps to `authn.Identity` as follows:

- `Provider`: `oauth`;
- `Issuer`: canonical HTTPS GitHub web origin;
- `Subject`: decimal GitHub numeric user ID;
- `LinkID`: `github:<issuer>:<subject>`;
- `DisplayName`: trimmed `name`, falling back to `login`.

Issuer canonicalization lowercases the host, removes a trailing slash and the
default HTTPS port, preserves a non-default port, and rejects userinfo, query,
fragment, or a non-root path. Numeric ID must be positive. Login and optional
name must be bounded valid UTF-8 without control characters, and the final
identity must pass existing `authn.Identity` validation.

The authorization request omits `scope` entirely. Token exchange requires a
non-empty bearer token and rejects every non-empty granted scope. Refresh and
expiry metadata are ignored. The access token stays in callback-local memory,
is never persisted, returned, logged, audited, measured, or passed to the
GitHub App, and is discarded after the authenticated-user request.

## Configuration and Runtime

`config.SSO` gains GitHub OAuth client ID and client-secret-file settings:

- `GREPNEST_OAUTH_GITHUB_CLIENT_ID`;
- `GREPNEST_OAUTH_GITHUB_CLIENT_SECRET_FILE`.

Both absent disables GitHub OAuth; both present enables it; a partial pair is a
startup error. Any enabled browser provider requires PostgreSQL and a valid
HTTPS public origin. Break-glass requires at least one enabled external browser
provider. Secret loading reuses the existing bounded regular-file reader and
rejects empty or whitespace-only content.

The server creates one shared session manager when OIDC, GitHub OAuth, or valid
break-glass authentication is active. Providers are registered in deterministic
OIDC-then-GitHub order. Existing public-origin enforcement, session cookies,
logout, bearer authentication, and MCP wiring remain unchanged.

Compose and Helm mirror the existing OIDC secret-file pattern: default-off
settings, an existing mounted secret, a read-only client-secret file, and no
inline secret value. GitHub OAuth reuses current GitHub egress and custom-CA
configuration; no independent OAuth endpoint overrides are added.

## Security and Failure Behavior

The shared flow preserves 32-byte random state and browser secrets, SHA-256
storage, PKCE S256, provider-bound one-time consumption, bounded exact-one
callback values, duplicate cookie rejection, replay and expiry rejection,
private response headers, cookie clearing, and a fixed safe failure redirect.
Flows cannot cross providers.

Token and user endpoints use bounded network timeouts, configured CA trust, and
redirect policy that prevents credential leakage across origins. Response
bodies are bounded before decoding. Errors expose only safe categories and
status codes and never include authorization codes, client secrets, tokens, or
untrusted response bodies.

Audit adds `oauth_login_succeeded` and `oauth_login_denied` with authentication
method `oauth`. Metrics use fixed low-cardinality method/provider labels only.
Issuer, login, numeric ID, subject, LinkID, state, code, and tokens are never
labels or audit fields.

## Verification

Unit coverage will exercise the shared flow's successful and invalid callback
paths, cookies, provider binding, replay, PKCE, auditing, and safe errors. Local
TLS GitHub fixtures will cover endpoints, no-scope authorization, token
validation, custom CA, redirect rejection, bounded responses, identity mapping,
and canary-secret exclusion from errors.

Configuration tests will cover every provider combination and malformed secret
or origin. PostgreSQL tests will cover migration constraints, exact SCIM
linking, immutable identity reuse, OAuth sessions, concurrency, expiry,
cleanup, and audit atomicity. Cross-replica E2E will begin login on one server,
complete it on another, verify REST and logout, reject replay and MCP cookies,
and preserve bearer and mixed-credential behavior.

The final gate is the repository's complete current suite: formatting, lint,
static analysis, vulnerability scanning, unit and race tests, PostgreSQL
integration, integration, E2E, build, Compose, Helm, image, OpenAPI, diff, and
secret-canary checks.

## Documentation and Manual Validation

README, architecture, threat model, operations, OpenAPI examples where needed,
Compose, and Helm documentation will explain provider combinations, callback
registration, exact SCIM `externalId`, no-scope and no-token-persistence
policies, secret rotation and revocation, diagnostics, GitHub App separation,
bearer-only MCP, and unverified GHES status.

The documented GitHub.com smoke test will use a dedicated OAuth App per
environment, exact HTTPS callback registration, a secret file, an active SCIM
user linked as `github:https://github.com:<numeric-id>`, provider metadata and
session-method checks, authorized REST access, logout, and the specified
negative cases without printing secrets or tokens.

## Explicit Non-Goals

This change does not add generic arbitrary OAuth identity mapping, SAML, device
flow, GitHub App user-to-server authentication, just-in-time provisioning,
email or login-name linking, token refresh or storage, OAuth repository access,
OAuth-authenticated MCP, multiple GitHub OAuth providers, separate identity and
repository GitHub hosts, provider logos, or external UI assets.
