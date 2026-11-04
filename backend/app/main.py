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
    aleana
)

app = FastAPI(
    title="VantaVisionAI Funding Prototype",
    description="Vision AI Security Scanner, Controlled Brain Command Interface, and Threat Intelligence",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

# Root directory resolution
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
static_dir = os.path.join(project_root, "static")

# Mount static frontend if directory exists
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/", include_in_schema=False)
@app.get("/index.html", include_in_schema=False)
async def serve_index():
    root_index = os.path.join(project_root, "index.html")
    if os.path.exists(root_index):
        return FileResponse(root_index)
    static_index = os.path.join(static_dir, "index.html")
    if os.path.exists(static_index):
        return FileResponse(static_index)
    return {"status": "ok", "message": "VantaVisionAI Funding Prototype API", "docs": "/docs"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
