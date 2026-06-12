"""
ShadowTrace FastAPI entrypoint.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.database.db import init_db
from backend.api.routes import router

settings = get_settings()

app = FastAPI(title="ShadowTrace API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.on_event("startup")
async def startup_event():
    init_db()


@app.get("/", tags=["root"])
async def root() -> dict:
    return {"status": "ShadowTrace API is running"}
