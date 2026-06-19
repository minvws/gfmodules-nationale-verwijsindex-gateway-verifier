# NVI Gateway Verifier

This app is the Nationale Verwijsindex Gateway Verifier and is part of the 'Generieke Functies, lokalisatie en addressering' project of the Ministry of Health, Welfare and Sport of the Dutch government. This repository contains a FastAPI service that verifies incoming gateway requests for OIN-based identity.
It validates both:

- The client certificate chain from `X-Forwarded-Tls-Client-Cert`
- The bearer JWT from the `Authorization` header

After successful validation, the service returns normalized identity headers, and it can optionally proxy
the request to a configured backend URL.

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

The verifier combines mTLS certificate checks and JWT checks in one place.

Validation behavior:

- Requires `Authorization: Bearer <token>`
- Requires a valid client certificate chain signed by the configured OIN CA
- Extracts OIN from the leaf certificate `subject.serialNumber` (must be 20 digits)
- Validates JWT signature and claims (`iss`, `aud`, `exp`, `nbf`, `iat`) against configured issuer/audience and JWKS
- Verifies JWT `cnf["x5t#S256"]` matches the leaf certificate SHA-256 fingerprint
- Verifies JWT OIN (`oin` or `oin_number`) matches certificate OIN

On success, identity headers are returned (and used by `/proxy`):

- `x-gf-cert-type`
- `x-gf-audience`
- `x-gf-scope`
- `x-gf-oin` (if present in token)
- `x-gf-source-id` (if present in token)

## Endpoints

- `GET /` ASCII home page with service logo and version details (when `version.json` exists)
- `GET /version.json` raw version metadata (`404` when missing)
- `GET /health` service health response
- `GET /validate` validates certificate + token and returns identity headers as JSON
- `GET|POST|PUT|PATCH|DELETE /proxy` runs `/validate` logic and forwards request to `kong_proxy.url` when enabled

See also [docs/kong.md](docs/kong.md) for proxy behavior details.

## Getting Started

You can run this service natively or with Docker.
If needed before testing, generate dummy secrets with `bash tools/generate_test_certs.sh`.

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

## Example Validate Call

```bash
curl -i http://localhost:8503/validate \
  -H "Authorization: Bearer <jwt>" \
  -H "X-Forwarded-Tls-Client-Cert: <url-encoded-pem-chain>"
```

Expected outcomes:

- `200` for valid cert + token + matching OIN/fingerprint
- `401` for missing/invalid bearer header
- `403` when certificate authentication fails
- `400` for token/fingerprint/claim mismatches

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
