import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from app.routers import auth

from app.database import engine, Base
from app.models import Scan, Finding, User

from app.core.config import APP_TITLE, APP_VERSION, APP_DESCRIPTION, STATIC_DIR

from app.routers import pages
from app.routers import url_scans
from app.routers import file_scans
from app.routers import history
from app.routers import scan_details
from app.routers import reports

# Initialize FastAPI application
app = FastAPI(title=APP_TITLE, version=APP_VERSION, description=APP_DESCRIPTION)
secret_key = os.environ.get("LINKSHIELD_SECRET_KEY")

if not secret_key:
    raise RuntimeError("LINKSHIELD_SECRET_KEY is not configured.")

app.add_middleware(
    SessionMiddleware,
    secret_key=secret_key,
    max_age=3600,
    same_site="lax",
    https_only=False,
)
# Create database tables
Base.metadata.create_all(bind=engine)

# Connect static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Register application routers
app.include_router(pages.router)
app.include_router(url_scans.router)
app.include_router(file_scans.router)
app.include_router(history.router)
app.include_router(scan_details.router)
app.include_router(reports.router)
app.include_router(auth.router)


# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "LinkShield is running", "version": APP_VERSION}
