import re
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.logging.context import (
    client_trace_id_var,
    endpoint_var,
    ip_var,
    method_var,
    request_id_var,
)

REQUEST_ID_HEADER = "X-Request-ID"
CLIENT_TRACE_ID_HEADER = "X-Client-Trace-ID"

_SAFE_HEADER_VALUE = re.compile(r"[^a-zA-Z0-9\-_]")


def _sanitize(value: str) -> str:
    return _SAFE_HEADER_VALUE.sub("", value)[:64]


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Populates the logging context (request_id, ip, endpoint, method, ...) for
    the duration of each request so every audit event carries it automatically."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = str(uuid.uuid4())
        ip = request.client.host if request.client else "-"
        client_trace_id = _sanitize(request.headers.get(CLIENT_TRACE_ID_HEADER, "-"))

        token_id = request_id_var.set(request_id)
        token_ip = ip_var.set(ip)
        token_trace = client_trace_id_var.set(client_trace_id)
        token_endpoint = endpoint_var.set(request.url.path)
        token_method = method_var.set(request.method)
        try:
            response = await call_next(request)
            response.headers[REQUEST_ID_HEADER] = request_id
            if client_trace_id != "-":
                response.headers[CLIENT_TRACE_ID_HEADER] = client_trace_id
            return response
        finally:
            request_id_var.reset(token_id)
            ip_var.reset(token_ip)
            client_trace_id_var.reset(token_trace)
            endpoint_var.reset(token_endpoint)
            method_var.reset(token_method)
