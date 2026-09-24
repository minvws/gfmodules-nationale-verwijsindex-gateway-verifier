# Gateway Verifier

This app is the Gateway Verifier for the NVI and PRS and is part of the 'Generieke Functies, lokalisatie en addressering' project of the Ministry of Health, Welfare and Sport of the Dutch government. This repository contains a FastAPI service that validates protected gateway requests using a bearer JWT and the acting identity supplied by the gateway.

> [!CAUTION]
>
> ## Disclaimer
>
> This project and all associated code serve solely as **documentation and demonstration purposes**
> to illustrate potential system communication patterns and architectures.
>
> This codebase:
>
> - Is NOT intended for production use
> - Does NOT represent a final specification
> - Should NOT be considered feature-complete or secure
> - May contain errors, omissions, or oversimplified implementations
> - Has NOT been tested or hardened for real-world scenarios
>
> The code examples are *only* meant to help understand concepts and demonstrate possibilities.
>
> By using or referencing this code, you acknowledge that you do so at your own risk and that
> the authors assume no liability for any consequences of its use.

## What This Service Does

In production, Kong processes a protected request in this order:

1. The `cert-info` Kong plugin injects `X-GF-Act-Sub` and `X-GF-Act-Cn`.
2. The `gateway-verifier` Kong plugin requires a bearer token and those acting
   identity headers, then calls the configured Gateway Verifier FastAPI
   service's `/validate` endpoint through its `verifier_url`.
3. The service validates the JWT and checks that `act.sub` and `act.cn` match
   the supplied acting values. It does not perform certificate validation.
4. On a `200` response, the `gateway-verifier` plugin injects the returned
   `x-gf-*` identity values into the upstream request and Kong continues to the
   backend.

The Gateway Verifier service is deployed once for NVI and once for PRS. The
corresponding `gateway-verifier` Kong plugin configuration points `verifier_url`
to that deployment. A non-`200` response from the service is returned by the
plugin as `401`; a connection failure or an invalid JSON response from the
service becomes `502`.

The Gateway Verifier service:

- Requires `Authorization: Bearer <token>`, `X-GF-Act-Sub`, and `X-GF-Act-Cn`
- Validates JWT signature and claims (`iss`, `aud`, `exp`, `nbf`, `iat`) against configured issuer/audience and JWKS
- Requires JWT `act.sub` and `act.cn` to match `X-GF-Act-Sub` and `X-GF-Act-Cn`

On success, `/validate` returns these identity values as JSON:

- `x-gf-cert-type`
- `x-gf-audience`
- `x-gf-scope`
- `x-gf-sub`
- `x-gf-act-sub`
- `x-gf-act-cn`
- `x-gf-organization-name`
- `x-gf-client-id`
- `x-gf-source-id` (when the signed `source_id` claim has a value)

For local development, where Kong is not handling verification, the
development-only `/proxy` endpoint simulates the `gateway-verifier` Kong plugin
by validating the request, setting the verified `x-gf-*` identity headers, and
forwarding the request. See [docs/kong.md](docs/kong.md) for its behavior.

## Endpoints

- `GET /` ASCII home page with service logo and version details (when `version.json` exists)
- `GET /version.json` raw version metadata (`404` when missing)
- `GET /health` service health response
- `GET /validate` validates the bearer JWT and acting identity headers, then returns identity values as JSON
- Development-only: `GET|POST|PUT|PATCH|DELETE /proxy` and `/proxy/{upstream_path:path}` validate and forward requests to `kong_proxy.url` when enabled
- Development-only: `GET|POST|PUT|PATCH|DELETE /proxy/health` provides an unauthenticated backend health passthrough

See [docs/kong.md](docs/kong.md) for development proxy details.

## Getting Started

You can run this service natively or with Docker.

### Docker (preferred)

If you run Linux, export your user and group IDs so mounted files keep correct ownership:

```bash
export NEW_UID=$(id -u)
export NEW_GID=$(id -g)
```

Start the service:

```bash
docker compose up
```

The service port is configured in `app.conf` / `app.conf.example` (`8503` by default).

### Native

Install dependencies and run with Poetry:

```bash
poetry install
poetry run python -m app.main
```

## Usage

The `gateway-verifier` Kong plugin calls `/validate` after the `cert-info` Kong
plugin has set `X-GF-Act-Sub` and `X-GF-Act-Cn`. The endpoint can also be called
directly for local testing:

```bash
curl -i http://localhost:8503/validate \
  -H "Authorization: Bearer <jwt>" \
  -H "X-GF-Act-Sub: <jwt-act-sub>" \
  -H "X-GF-Act-Cn: <jwt-act-cn>"
```

In a direct request, supply the acting headers manually with values matching the
JWT `act.sub` and `act.cn` claims.

Expected direct service responses:

- `200` for a valid JWT with matching acting identity values
- `400` for JWT verification failures, required claim failures, or acting identity mismatches
- `401` for a malformed non-Bearer `Authorization` header
- `500` when required gateway headers are missing

## Docker Image Builds

Default image build:

```bash
make container-build
```

Standalone image build (uses `docker/init-standalone.sh`, expects mounted `app.conf`):

```bash
make container-build-sa
```

## Installation

Docker images are published to the [GitHub Container Registry](https://ghcr.io/minvws/gfmodules-nationale-verwijsindex-gateway-verifier)

You can pull the latest image with the following command:

```bash
docker pull ghcr.io/minvws/gfmodules-nationale-verwijsindex-gateway-verifier:latest
```

## Contribution

As stated in the [disclaimer](#disclaimer) this project and all associated code serve solely as documentation and
demonstration purposes to illustrate potential system communication patterns and architectures.

For that reason we will only accept contributions that fit this goal. We do appreciate any effort from the
community, but because our time is limited it is possible that your PR or issue is closed without a full justification.

If you plan to make non-trivial changes, we recommend to open an issue beforehand where we can discuss your planned changes. This increases the chance that we might be able to use your contribution (or it avoids doing work if there are reasons why we wouldn't be able to use it).

Note that all commits should be signed using a gpg key.

To keep local editor/IDE files out of version control, configure a global ignore file:

```bash
git config --global core.excludesfile ~/.gitignore
```
