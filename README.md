<div align="center">

# GrepNest

**Self-hosted code search and relationship-aware code intelligence for humans and AI agents.**

[![CI](https://github.com/balcsida/grep-nest/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/balcsida/grep-nest/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/balcsida/grep-nest?display_name=tag&sort=semver)](https://github.com/balcsida/grep-nest/releases/latest)
[![License](https://img.shields.io/github/license/balcsida/grep-nest)](LICENSE)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.25%2B-326CE5)](deploy/helm/grepnest/README.md)

</div>

GrepNest is an experimental, self-hosted code search and context layer for engineering teams and AI agents. Authorized clients can search GitHub repositories, open files at the exact indexed commit, follow symbols across repositories, and inspect dependency and impact relationships without receiving direct access to the underlying search index.

Under the hood, GrepNest combines fast [Zoekt](https://github.com/sourcegraph/zoekt) search, [SCIP](https://github.com/sourcegraph/scip) code navigation, and a rebuildable [LadybugDB](https://github.com/LadybugDB/ladybug) relationship graph behind web, REST, and MCP interfaces.

> [!IMPORTANT]
> GrepNest is **pre-1.0 pilot software**. It is not production-ready, currently indexes default branches only, and has not yet been validated at production scale or certified against a live GitHub Enterprise Server or OpenShift environment. See [Compatibility](docs/compatibility.md) for the current boundaries.

![GrepNest code search with SCIP navigation](docs/images/grepnest-ui.png)

## What GrepNest provides

| Capability | Description |
| --- | --- |
| **Fast, scoped code search** | Search authorized repositories through a server-controlled Zoekt backend. Clients never receive direct Zoekt access or choose raw Zoekt repository IDs. |
| **Exact indexed revisions** | Open files at the precise indexed commit. Search results are suppressed when Zoekt and PostgreSQL disagree about the current indexed SHA. |
| **Cross-repository code navigation** | Upload pre-generated SCIP indexes to navigate definitions, references, and implementations without running language indexers inside GrepNest. |
| **Relationship-aware graph analysis** | Explore context, impact, and dependency paths through a derived LadybugDB graph. Administrators can also run bounded, read-only Cypher queries. |
| **Human and agent interfaces** | Use the embedded browser console, REST API, hosted Streamable HTTP MCP endpoint, or the `grepnest-mcp` stdio proxy. |
| **GitHub-native repository management** | Reconcile GitHub App installations, verify webhook signatures, queue default-branch indexing, support private CAs, and retain numeric GitHub repository identity across renames. |
| **Durable identity and access** | Use OIDC or GitHub OAuth browser sign-in, SCIM 2.0 provisioning, revocable API tokens, user and group repository assignments, administrative controls, and security audit events. |
| **Pilot deployment tooling** | Run locally with Docker Compose or deploy the single-node pilot with Helm. Releases publish multi-architecture images, an OCI chart, SBOMs, provenance, and GitHub attestations. |

Native graph scanners currently support **Go, JavaScript, TypeScript/TSX, Java, Kotlin, and Rust**. SCIP uploads remain a separate, language-indexer-independent navigation path.

## Architecture

```mermaid
flowchart LR
    Client[Web UI / REST / MCP] --> Server[grepnest-server]

    Server -->|GitHub App API| GitHub[GitHub.com or GHES]
    GitHub -->|Signed webhooks| Server
    Indexer[grepnest-indexer] -->|Fetch default branch| GitHub
    Scanner[grepnest-scanner] -->|Graph artifacts| Postgres[(PostgreSQL)]

    Server --> Postgres
    Indexer --> Postgres
    Postgres --> Indexer
    Indexer --> Zoekt[(Zoekt index)]
    Server --> Zoekt

    Postgres --> Graph[Embedded or separate graph runtime]
    Graph --> Ladybug[(LadybugDB derived store)]
    Server --> Graph
```

PostgreSQL is authoritative for repository metadata, authorization, queues, indexed-SHA state, and graph artifacts. Zoekt and LadybugDB are private query stores reached only through GrepNest's authenticated services. See [Architecture](docs/architecture.md) and the accepted decisions under [`docs/adr`](docs/adr).

## Interfaces

| Interface | Location | Authentication |
| --- | --- | --- |
| Browser console | `/` | Development bearer token or durable OIDC or GitHub OAuth session |
| REST API | `/v1/...` | Bearer token or, where supported, same-origin browser session |
| Streamable HTTP MCP | `/mcp` | Bearer token |
| Stdio MCP proxy | `grepnest-mcp` | Uses `GREPNEST_SERVER_URL` and `GREPNEST_TOKEN` |
| Health and observability | `/healthz`, `/readyz`, `/metrics` | Intended for deployment health checks and monitoring |

The complete REST contract is available in [`docs/openapi.yaml`](docs/openapi.yaml).

## Local quick start

The fixture profile is the fastest way to try GrepNest. It starts a deterministic test repository and Zoekt index while the server runs on the host.

### Prerequisites

- Go 1.26.5
- Git
- Docker with Docker Compose
- `jq`
- Internet access for Go tools and container images

### 1. Start the fixture index

```sh
git clone https://github.com/balcsida/grep-nest.git
cd grep-nest

make tools
docker compose -f deploy/compose/compose.yml --profile fixture up -d --wait
```

The fixture is indexed as repository `fixture/repository` with Zoekt repository ID `7`.

### 2. Start GrepNest

In another terminal:

```sh
GREPNEST_LISTEN_ADDRESS=127.0.0.1:8080 \
GREPNEST_ZOEKT_URL=http://127.0.0.1:6070 \
GREPNEST_REPOSITORIES_FILE=deploy/compose/repositories.json \
GREPNEST_USER_TOKEN=grepnest-dev-user-token \
GREPNEST_ADMIN_TOKEN=grepnest-dev-admin-token \
GREPNEST_USER_REPOSITORIES=fixture/repository \
GREPNEST_ADMIN_REPOSITORIES=fixture/repository \
go run ./cmd/grepnest-server
```

Open <http://127.0.0.1:8080/> and sign in with:

```text
grepnest-dev-user-token
```

The browser keeps this development token only for the current session.

### 3. Search through REST

```sh
curl --fail-with-body http://127.0.0.1:8080/v1/search \
  -H 'Authorization: Bearer grepnest-dev-user-token' \
  -H 'Content-Type: application/json' \
  --data '{
    "query": "GrepNestFixtureNeedle",
    "repositories": ["fixture/repository"]
  }'
```

Requests for repositories outside the authenticated principal's scope return no matches rather than revealing whether those repositories exist.

### 4. Stop the fixture

```sh
docker compose -f deploy/compose/compose.yml --profile fixture down
```

## Connect an MCP client

MCP clients that support Streamable HTTP can connect directly to:

```text
http://127.0.0.1:8080/mcp
```

Send the same bearer token in the `Authorization` header. The core tools include code search and file discovery; durable mode additionally exposes symbol navigation and graph-backed analysis.

For a stdio-only MCP client, build the proxy:

```sh
go build -o /tmp/grepnest-mcp ./cmd/grepnest-mcp

GREPNEST_SERVER_URL=http://127.0.0.1:8080 \
GREPNEST_TOKEN=grepnest-dev-user-token \
/tmp/grepnest-mcp
```

The proxy appends `/mcp` automatically and does not connect to Zoekt directly.

GrepNest also ships optional graph-analysis skills for agent clients. Installation is explicit and does not happen during normal proxy startup:

```sh
/tmp/grepnest-mcp install-skills --root /path/to/repository
```

The installer writes GrepNest-owned content under `.claude/skills/` and mirrors it to `.agents/skills/` only when `.agents/` already exists.

## SCIP code navigation

GrepNest stores SCIP indexes but does not generate them. Produce the `.scip` file in each repository's CI for the same 40-character lowercase commit SHA reported by GrepNest as `indexed_sha`, then upload it with an administrator token:

```sh
scip-go

curl --fail-with-body -X POST \
  "https://grepnest.example/v1/scip/uploads?repository_id=101&commit=$GITHUB_SHA" \
  -H "Authorization: Bearer $GREPNEST_ADMIN_TOKEN" \
  -H 'Content-Type: application/vnd.scip+protobuf' \
  --data-binary @index.scip
```

Uploads for any commit other than the repository's exact indexed SHA are rejected. Cross-repository navigation can use manually supplied package URLs or metadata refreshed from GitHub's dependency graph. The exact endpoints, limits, and response schemas are defined in the [OpenAPI contract](docs/openapi.yaml).

## Durable mode

Static fixture mode is intentionally small. Durable mode adds PostgreSQL-backed repository state, GitHub App reconciliation, verified webhook ingestion, queued indexing, exact-SHA file reads, identity management, and graph analysis.

A durable deployment consists of:

- `grepnest-server` for the web UI, REST, MCP, authentication, authorization, and GitHub reconciliation;
- one `grepnest-indexer` for leased default-branch indexing and Zoekt publication;
- zero or more `grepnest-scanner` workers for native graph extraction;
- one graph owner, embedded in the indexer by default or running as `grepnest-graph`;
- PostgreSQL as the authoritative state store; and
- Zoekt plus LadybugDB as private query infrastructure.

The Compose deployment requires application and node images, PostgreSQL, GitHub App credentials, an internal graph secret, and the server settings documented in [Operations](docs/operations.md). Start one graph topology only:

```sh
docker compose \
  -f deploy/compose/compose.yml \
  -f deploy/compose/durable.yml \
  -f deploy/compose/graph-embedded.yml \
  --profile durable \
  up -d --wait
```

Replace `graph-embedded.yml` with `graph-separate.yml` to run a standalone graph owner.

## Authentication and authorization

| Purpose | Mechanism |
| --- | --- |
| Local fixture access | Distinct development-only user and administrator bearer tokens |
| Browser sign-in | OIDC or GitHub OAuth Authorization Code flow with PKCE and an opaque, HttpOnly GrepNest session |
| REST and MCP access | Revocable bearer API tokens; `/mcp` remains bearer-only |
| Directory provisioning | Optional SCIM 2.0 endpoint protected by a dedicated secret-file token |
| Emergency administration | Disabled-by-default local recovery flow provisioned offline with `grepnest-admin` |

Authorization is enforced by the server against current repository IDs and directory state. Repository names are selectors, not security identities. Deactivated users and revoked credentials are denied on their next request.

GitHub OAuth uses a dedicated OAuth App per environment, separate from the GitHub App used for repository access. Configure `GREPNEST_PUBLIC_URL`, `GREPNEST_OAUTH_GITHUB_CLIENT_ID`, and `GREPNEST_OAUTH_GITHUB_CLIENT_SECRET_FILE`, then register `https://<public-host>/auth/oauth/github/callback`. The flow requests no scope and uses the access token once for `GET /user`; the token is then discarded and cannot authenticate MCP. GitHub Enterprise Server OAuth remains unverified.

OIDC, GitHub OAuth, SCIM, API-token administration, audit events, and break-glass recovery require durable mode. See [Operations](docs/operations.md) and the [Threat model](docs/threat-model.md) before exposing the service.

## Kubernetes and Helm

The chart under [`deploy/helm/grepnest`](deploy/helm/grepnest) targets Kubernetes 1.25 or newer and models a generic single-node pilot. It expects operator-managed PostgreSQL and existing Kubernetes Secrets; it does not install a database or place plaintext credentials in chart values.

Released OCI charts embed immutable application and node image digests. For the current chart version:

```sh
helm pull oci://ghcr.io/balcsida/grep-nest/charts/grepnest --version 0.2.0
helm upgrade --install grepnest grepnest-0.2.0.tgz \
  --namespace grepnest \
  --create-namespace \
  --values my-values.yaml \
  --wait \
  --timeout 15m
```

Review the [Helm chart documentation](deploy/helm/grepnest/README.md) for required images, Secrets, storage, ingress, network policies, OIDC, GitHub OAuth, SCIM, scanners, graph topology, monitoring, and recovery procedures. Release notes contain immutable artifact references and attestation-verification commands.

## Current limits

- GrepNest is pre-1.0 pilot software and makes no stable compatibility promise.
- Only default branches are indexed.
- The default GHES contract targets GitHub Enterprise Server 3.17 with REST API version `2022-11-28`; this has not been certified against a live GHES deployment.
- Kubernetes, OpenShift, backup and restore, upgrade and rollback, ingress, and production-scale capacity still require environment-specific validation.
- Native graph scanning is not equivalent to a full language server or language-specific indexer.
- GrepNest does not currently provide embedding-based semantic search.
- LadybugDB is derived and rebuildable; it is not a backup or authorization source.

Read [Compatibility](docs/compatibility.md), [Benchmarking](docs/benchmarking.md), and [Operations](docs/operations.md) before planning a pilot.

## Build and test

Build the commands and local images with:

```sh
make build
make image-test
```

Run the main verification suites with:

```sh
make fmt lint staticcheck govulncheck
make test test-race integration e2e
make openapi-check compose-test helm-lint helm-test
```

CI additionally exercises native LadybugDB linking, scanner grammar compatibility, UI smoke tests, and release packaging. Some targets download pinned tools or native libraries and require Docker.

## Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Service boundaries, authorization flow, indexing, and graph ownership |
| [Operations](docs/operations.md) | Local and durable operation, recovery, identity, and graph runbooks |
| [OpenAPI](docs/openapi.yaml) | Canonical REST request, response, security, and limit contract |
| [Helm chart](deploy/helm/grepnest/README.md) | Kubernetes configuration, Secrets, storage, networking, and installation |
| [Compatibility](docs/compatibility.md) | Supported contracts, platforms, languages, and unverified boundaries |
| [Threat model](docs/threat-model.md) | Protected assets, security controls, and known limits |
| [Benchmarking](docs/benchmarking.md) | Measurement guidance for pilot sizing |
| [Release process](docs/release-process.md) | Signed tags, images, OCI chart, attestations, and release verification |
| [Implementation report](docs/implementation-report.md) | Delivered milestones, verification evidence, risks, and deferred work |
| [Dependency pinning](docs/dependency-pinning.md) | Reproducibility and pinned dependency policy |

## Contributing and support

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change. Keep changes within an accepted milestone, include tests for behavior changes, and preserve the boundary that Zoekt is private implementation infrastructure.

Use [GitHub Issues](https://github.com/balcsida/grep-nest/issues) for reproducible bugs and feature discussions, and read [SUPPORT.md](SUPPORT.md) for the project's support boundaries. Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Report suspected vulnerabilities through the private process in [SECURITY.md](SECURITY.md), not through a public issue.

## License

GrepNest is licensed under the [Apache License 2.0](LICENSE).
