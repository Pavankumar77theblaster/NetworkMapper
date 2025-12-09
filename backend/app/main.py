from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import init_db
from app.api.routes import devices, scans, findings
from app.api import websocket

# Create FastAPI app
app = FastAPI(
    title="Network Device Mapper API",
    description="Cyberpunk-themed network device mapper with pentesting features",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allow_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(devices.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(findings.router, prefix="/api")
app.include_router(websocket.router)  # WebSocket at /ws


@app.on_event("startup")
async def startup_event():
    """Initialize database and WebSocket callback."""
    init_db()

    # Set WebSocket callback for scan orchestrator
    from app.api.websocket import websocket_callback
    scans.set_websocket_callback(websocket_callback)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Network Device Mapper API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=settings.DEBUG)
