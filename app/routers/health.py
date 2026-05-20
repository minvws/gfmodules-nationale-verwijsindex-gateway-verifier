import logging
from typing import Dict

from fastapi import APIRouter
from fastapi.responses import JSONResponse

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
def health() -> JSONResponse:
    logger.info("Checking database health")

    components: Dict[str, str] = {}
    healthy = ok_or_error(all(value == "ok" for value in components.values()))
    content = {"status": healthy, "components": components}
    if healthy == "ok":
        return JSONResponse(content=content)
    logger.warning(f"Some components unhealthy: {components}")
    return JSONResponse(
        status_code=503,
        content=content,
    )
