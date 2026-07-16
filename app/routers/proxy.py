import json
import logging
from typing import Annotated

import requests as http_requests
from fastapi import APIRouter, Depends, Request, Response

from app.config import get_config
from app.container import get_jwt_service
from app.routers.validator import run_validate
from app.services.jwt import JWTService

logger = logging.getLogger(__name__)
router = APIRouter()

# Connection-specific request headers that must not be forwarded verbatim;
# requests sets Host/Content-Length itself for the backend call.
_SKIP_REQUEST_HEADERS = {"host", "content-length", "connection"}

# Backend response headers that requests recomputes for our client.
_SKIP_RESPONSE_HEADERS = {"content-length", "transfer-encoding", "connection", "content-encoding"}

# Paths (below /proxy) forwarded without authentication, so orchestration and
# upstream health probes can check backend reachability without a bearer token.
_UNAUTHENTICATED_PATHS = {"health"}


@router.api_route("/proxy", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@router.api_route("/proxy/{upstream_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(
    request: Request,
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
    upstream_path: str = "",
) -> Response:
    """Authenticated reverse proxy that replaces a Kong layer.

    Runs the same mTLS + JWT validation as ``/validate`` and, on success,
    forwards the original request to the configured backend
    (``kong_proxy.url``) with the verified ``x-gf-*`` identity headers attached.
    The request method, path (below ``/proxy``), query string and body are all
    preserved, so the endpoint can transparently front a REST backend.
    """
    config = get_config()

    if not config.kong_proxy.enabled:
        return Response("Kong proxy is not enabled", status_code=503)

    # Validate the request using the same logic as /validate, except for the
    # unauthenticated health passthrough (used by upstream health probes).
    identity: dict[str, object] = {}
    if upstream_path not in _UNAUTHENTICATED_PATHS:
        validate_response = run_validate(request, jwt_service)
        if validate_response.status_code != 200:
            return validate_response
        identity = json.loads(bytes(validate_response.body))

    # Forward the caller's headers (client certificate, content-type, ...), but
    # strip any client-supplied x-gf-* so the identity cannot be spoofed, then
    # overlay the verified identity from the validate response.
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in _SKIP_REQUEST_HEADERS and not key.lower().startswith("x-gf-")
    }
    headers.update(
        {key: str(value) for key, value in identity.items() if key.startswith("x-gf-") and value is not None}
    )

    # Preserve the request path and query string on the backend URL.
    target = config.kong_proxy.url.rstrip("/")
    if upstream_path:
        target = f"{target}/{upstream_path}"
    if request.url.query:
        target = f"{target}?{request.url.query}"

    # Forward the original request body using the same HTTP method
    body = await request.body()
    backend_response = http_requests.request(request.method, target, headers=headers, data=body, timeout=30)

    response_headers = {
        key: value for key, value in backend_response.headers.items() if key.lower() not in _SKIP_RESPONSE_HEADERS
    }
    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=response_headers,
    )
