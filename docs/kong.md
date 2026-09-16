# Development Proxy

The development-only `/proxy` endpoint locally combines validation, identity
header enrichment, and backend forwarding. Enable it for local development
where Kong is not handling verification.

## Production flow

In production, Kong first runs the `cert-info` Kong plugin, which injects
`X-GF-Act-Sub` and `X-GF-Act-Cn`. The `gateway-verifier` Kong plugin then
requires those headers and a bearer token, and calls the configured Gateway
Verifier FastAPI service's `/validate` endpoint through its `verifier_url`.
The Gateway Verifier service is deployed once for NVI and once for PRS. The
corresponding `gateway-verifier` Kong plugin configuration points `verifier_url`
to that deployment.

The service validates the JWT and acting values; it does not perform certificate
validation. On a `200` response, the `gateway-verifier` plugin injects the
returned `x-gf-*` identity values into the upstream request and Kong continues.
It translates a non-`200` service response to `401`, and a connection failure
or invalid JSON response to `502`.

## How it works

1. For protected paths, `/proxy` accepts GET, POST, PUT, PATCH, and DELETE
   requests carrying `Authorization: Bearer <token>`, `X-GF-Act-Sub`, and
   `X-GF-Act-Cn` headers. Our `cert-info` Kong plugin normally populates the two
   `X-GF-Act-*` headers before the `gateway-verifier` plugin calls the Gateway
   Verifier service to verify the request; local callers supply them manually
   to emulate `cert-info`.
2. The development proxy verifies the JWT signature and its configured issuer,
   audience, and time claims (`exp`, `nbf`, and `iat`). It then compares the JWT
   `act.sub` and `act.cn` claims with `X-GF-Act-Sub` and `X-GF-Act-Cn`.
3. Validation failures are returned to the client and are not forwarded to the
   backend.
4. After successful validation, the development proxy strips caller-supplied
   `x-gf-*` headers, except `X-GF-Correlation-ID` when
   `allow_client_correlation_id` is enabled, then overlays verified identity
   values. It normally produces
   `x-gf-cert-type`, `x-gf-audience`, `x-gf-scope`, `x-gf-act-sub`, and
   `x-gf-act-cn`. An absent `scope` claim produces `x-gf-scope` with an empty
   value; an explicitly null `scope` claim omits that header. It forwards
   `x-gf-sub` and `x-gf-organization-name` only when their JWT claims are
   non-null. When the signed `source_id` claim has a value, it also adds
   `x-gf-source-id`.
5. The original HTTP method, path below `/proxy`, query string, and request
   body are forwarded to `kong_proxy.url` with those headers attached.
6. The backend response status, body, and response headers are returned to the
   client.

`/proxy/health` is an unauthenticated health passthrough. It bypasses JWT
validation and forwards to the backend without injecting verified identity
headers.

## Configuration

Add a `[kong_proxy]` section to `app.conf`:

```ini
[kong_proxy]
enabled = True
url = https://your-backend/path
allow_client_correlation_id = False
```

| Setting | Description |
|---------|-------------|
| `enabled` | Set to `True` to activate the proxy endpoint. |
| `url` | The backend URL to which validated requests are forwarded. |
| `allow_client_correlation_id` | When `True`, forward the client-supplied `X-GF-Correlation-ID`; otherwise strip it. |

When `enabled = False`, `/proxy` returns `503 Service Unavailable`.

## Local development

For local development without Kong and its plugins, point `url` at
[httpbin](https://httpbin.org), which echoes back the headers it receives —
useful for verifying that the enriched headers are being forwarded correctly.
Supply
`X-GF-Act-Sub` and `X-GF-Act-Cn` manually, using values that match the signed
JWT's `act.sub` and `act.cn` claims:

```ini
[kong_proxy]
enabled = True
url = https://httpbin.org/headers
allow_client_correlation_id = False
```

Then send a request:

```bash
curl -X POST http://localhost:8503/proxy \
  -H "Authorization: Bearer <your-jwt>" \
  -H "X-GF-Act-Sub: <jwt-act-sub>" \
  -H "X-GF-Act-Cn: <jwt-act-cn>" \
  -H "Content-Type: application/json" \
  -d '{"example": "body"}'
```

The response from httpbin will show the verified `x-gf-*` identity headers that
were injected by the development proxy, mirroring the `gateway-verifier` Kong
plugin in production.
