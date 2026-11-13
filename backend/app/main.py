"""
VantaVisionAI Funding Prototype - FastAPI Main Application Entry Point
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.app.routers import (
    brain,
    events,
    incidents,
    policies,
    system,
    copilot,
    audit,
    demo,
    aleana,
    devices,
    infrastructure
)

app = FastAPI(
    title="VANTA AI — VantaVisionAI Universal Infrastructure Intelligence OS",
    description="Universal Infrastructure Intelligence OS, Multi-Device Vision AI, 9-Layer Vanta Brain, Industrial IoT, Predictive Maintenance, Energy Intelligence, and Digital Twin",
    version="2.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Tenant-ID", "X-Operator-Role", "X-Role"],
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Include all system and API v1 routers
app.include_router(system.router)
app.include_router(brain.router)
app.include_router(events.router)
app.include_router(incidents.router)
app.include_router(policies.router)
app.include_router(copilot.router)
app.include_router(audit.router)
app.include_router(demo.router)
app.include_router(aleana.router)
app.include_router(devices.router)
app.include_router(infrastructure.router)

# Root directory resolution
project_root = os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
static_dir = os.path.realpath(os.path.join(project_root, "static"))

# Mount static frontend if directory exists
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/manifest.json", include_in_schema=False)
async def serve_manifest():
    p = os.path.join(static_dir, "manifest.json")
    if os.path.exists(p):
        return FileResponse(p, media_type="application/manifest+json")
    return {"error": "manifest not found"}

@app.get("/sw.js", include_in_schema=False)
async def serve_sw():
    p = os.path.join(static_dir, "sw.js")
    if os.path.exists(p):
        return FileResponse(p, media_type="application/javascript")
    return {"error": "sw not found"}

@app.get("/{pwa_asset:path}", include_in_schema=False)
async def serve_root_or_pwa(pwa_asset: str = ""):
    if ".." in pwa_asset or "\x00" in pwa_asset:
        return {"error": "FORBIDDEN_PATH", "detail": "Directory traversal sequences are prohibited."}
    if pwa_asset in ("", "index.html"):
        root_index = os.path.join(project_root, "index.html")
        if os.path.exists(root_index):
            return FileResponse(root_index)
        static_index = os.path.join(static_dir, "index.html")
        if os.path.exists(static_index):
            return FileResponse(static_index)
        return {"status": "ok", "message": "VantaVisionAI API", "docs": "/docs"}
    candidate = os.path.realpath(os.path.join(static_dir, pwa_asset.lstrip("/")))
    if candidate.startswith(static_dir + os.sep) and os.path.isfile(candidate):
        return FileResponse(candidate)
    root_index = os.path.join(project_root, "index.html")
    if os.path.exists(root_index):
        return FileResponse(root_index)
    return {"status": "ok", "message": "VantaVisionAI API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)

