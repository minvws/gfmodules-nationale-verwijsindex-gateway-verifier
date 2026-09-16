# Kong Proxy

The `/proxy` endpoint is an authenticated gateway that validates a request and
forwards it to a configured backend URL. Enable it for local development when
Kong is not handling verification.

## How it works

1. For protected paths, `/proxy` accepts GET, POST, PUT, PATCH, and DELETE
   requests carrying `Authorization: Bearer <token>`, `X-GF-Act-Sub`, and
   `X-GF-Act-Cn` headers. Our `cert-info` Kong plugin normally populates the two
   `X-GF-Act-*` headers before forwarding the request; direct and local callers
   provide them manually to emulate the plugin.
2. The gateway verifies the JWT signature and its configured issuer, audience,
   and time claims (`exp`, `nbf`, and `iat`). It then compares the JWT
   `act.sub` and `act.cn` claims with `X-GF-Act-Sub` and `X-GF-Act-Cn`.
3. Validation failures are returned to the client and are not forwarded to the
   backend.
4. After successful validation, the gateway strips caller-supplied `x-gf-*`
   headers, except `X-GF-Correlation-ID` when `allow_client_correlation_id` is
   enabled, then overlays verified identity values. It normally produces
   `x-gf-cert-type`, `x-gf-audience`, `x-gf-scope`, `x-gf-act-sub`, and
   `x-gf-act-cn`. An absent `scope` claim produces `x-gf-scope` with an empty
   value; an explicitly null `scope` claim omits that header. It forwards
   `x-gf-sub` and `x-gf-organization-name` only when their JWT claims are
   non-null. When `source_id` is present in the signed JWT, it also adds
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
url = https://your-kong-service/path
allow_client_correlation_id = False
```

| Setting | Description |
|---------|-------------|
| `enabled` | Set to `True` to activate the proxy endpoint. |
| `url` | The backend URL to which validated requests are forwarded. |
| `allow_client_correlation_id` | When `True`, forward the client-supplied `X-GF-Correlation-ID`; otherwise strip it. |

When `enabled = False`, `/proxy` returns `503 Service Unavailable`.

## Local development

For local development without Kong and our `cert-info` plugin, point `url` at
[httpbin](https://httpbin.org), which echoes back the headers it receives — useful
for verifying that the enriched headers are being forwarded correctly. Supply
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
were injected by the gateway.
