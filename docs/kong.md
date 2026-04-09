# Kong Proxy

The `/proxy` endpoint acts as an authenticated gateway that validates an incoming request and forwards it to a 
configured backend URL. It can be enabled when developing locally and are not using a Kong system to handle 
verification.

This way, you can curl a request to the /proxy, and still have the verifier to run and enrich the headers before 
forwarding it to your backend.

## How it works

1. The client sends a request to `/proxy` using any HTTP method (GET, POST, PUT, PATCH, DELETE), including the 
   usual `Authorization: Bearer <token>` header and an mTLS client certificate.
2. The gateway runs the same validation logic as `/validate`:
   - Verifies the mTLS certificate is a valid OIN certificate
   - Verifies the JWT signature, issuer, audience, and expiry
   - Checks that the OIN in the JWT matches the OIN in the certificate
   - Looks up the OIN (and optional `X-Source-Id`) in the healthcare provider database
3. If validation fails, the error response is returned directly to the client (no forwarding).
4. If validation succeeds, the identity fields from the validation result are added as HTTP headers (`X-Oin-Number`, 
   `X-Ura-Number`, `X-Source-Id`, `X-Authorized-Role`, `X-Audience`).
5. The original request body is forwarded to `kong_proxy.url` using the same HTTP method, with those headers attached.
6. The backend response is returned as-is to the client.

## Configuration

Add a `[kong_proxy]` section to `app.conf`:

```ini
[kong_proxy]
enabled = True
url = https://your-kong-service/path
```

| Setting   | Description                                      |
|-----------|--------------------------------------------------|
| `enabled` | Set to `True` to activate the proxy endpoint     |
| `url`     | The backend URL to forward validated requests to |

When `enabled = False`, the `/proxy` endpoint returns `503 Service Unavailable`.

## Local development

For local development you can point `url` at [httpbin](https://httpbin.org), which echoes back the headers it receives — useful for 
verifying that the enriched headers are being forwarded correctly.

```ini
[kong_proxy]
enabled = True
url = https://httpbin.org/headers
```

Then send a request:

```bash
curl -X POST http://localhost:8503/proxy \
  -H "Authorization: Bearer <your-jwt>" \
  -H "X-Forwarded-Tls-Client-Cert: <url-encoded-pem>" \
  -H "Content-Type: application/json" \
  -d '{"example": "body"}'
```

The response from httpbin will show the `X-Oin-Number`, `X-Ura-Number`, `X-Source-Id`, `X-Authorized-Role`, and 
`X-Audience` headers that were injected by the gateway.

To test with a specific source ID, add the `X-Source-Id` header:

```bash
curl -X GET http://localhost:8503/proxy \
  -H "Authorization: Bearer <your-jwt>" \
  -H "X-Forwarded-Tls-Client-Cert: <url-encoded-pem>" \
  -H "X-Source-Id: my-source-system"
```
