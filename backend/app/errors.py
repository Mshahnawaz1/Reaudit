from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .models import ApiError, ApiErrorBody, ErrorCode

log = logging.getLogger("repoguard")


class AppError(Exception):
    def __init__(self, code: ErrorCode, message: str, status: int = 400, detail: str | None = None):
        super().__init__(message)
        self.code: ErrorCode = code
        self.message = message
        self.status = status
        self.detail = detail

    def to_api(self) -> ApiError:
        return ApiError(error=ApiErrorBody(code=self.code, message=self.message, detail=self.detail))


# default HTTP status per code
STATUS: dict[str, int] = {
    "invalid_url": 400, "unsupported_host": 400, "repo_not_found": 404,
    "repo_private_or_forbidden": 403, "repo_empty": 422, "repo_too_large": 413,
    "clone_timeout": 504, "job_not_found": 404, "job_not_ready": 409,
    "rate_limited": 429, "llm_unavailable": 503, "internal_error": 500,
}


def make_error(code: ErrorCode, message: str, detail: str | None = None) -> AppError:
    return AppError(code, message, STATUS[code], detail)


def _json(err: ApiError, status: int) -> JSONResponse:
    return JSONResponse(err.model_dump(exclude_none=True), status_code=status)


def install_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return _json(exc.to_api(), exc.status)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        code: ErrorCode = "invalid_url" if request.url.path == "/api/audit" else "internal_error"
        first = exc.errors()[0] if exc.errors() else {}
        loc = ".".join(str(x) for x in first.get("loc", ())[1:])
        msg = "Invalid request body" + (f" ({loc}: {first.get('msg')})" if loc else "")
        return _json(ApiError(error=ApiErrorBody(code=code, message=msg)), 400)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code: ErrorCode = "job_not_found" if exc.status_code == 404 else "internal_error"
        return _json(ApiError(error=ApiErrorBody(code=code, message=str(exc.detail))), exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error: %s", type(exc).__name__)
        return _json(
            ApiError(error=ApiErrorBody(code="internal_error", message="Internal server error")), 500
        )
