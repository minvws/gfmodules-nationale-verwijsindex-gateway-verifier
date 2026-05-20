import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.container import get_jwt_service
from app.services.jwt import JWTService

logger = logging.getLogger(__name__)
router = APIRouter()


def ok_or_error(value: bool) -> str:
    return "ok" if value else "error"


@router.get(
    "/health",
    summary="Health Check",
    description="health check for all dependent API services and components.",
    status_code=200,
    responses={
        200: {
            "description": "Health check completed (may contain unhealthy components)",
            "content": {
                "application/json": {
                    "examples": {
                        "all_healthy": {
                            "summary": "All services healthy",
                            "value": {
                                "status": "ok",
                            },
                        },
                    }
                }
            },
        },
        500: {"description": "Unexpected error during health check execution"},
        503: {
            "description": "One or more components are unhealthy",
            "content": {
                "application/json": {
                    "examples": {
                        "some_unhealthy": {
                            "summary": "Some services unhealthy",
                            "value": {
                                "status": "error",
                            },
                        },
                    }
                }
            },
        },
    },
    tags=["Health"],
)
def health(jwt_service: Annotated[JWTService, Depends(get_jwt_service)]) -> JSONResponse:
    logger.info("Checking database health")

    components = {
        "jwks_url": ok_or_error(jwt_service.health_check()),
    }
    healthy = ok_or_error(all(components.values()))
    content = {"status": healthy, "components": components}
    if healthy == "ok":
        return JSONResponse(content=content)
    unhealthy = [name for name, status in components.items() if status != "ok"]
    logger.warning(f"Unhealthy components: {', '.join(unhealthy)}")
    return JSONResponse(
        status_code=503,
        content=content,
    )
