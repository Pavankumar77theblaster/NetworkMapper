"""WebSocket endpoint for real-time scan updates."""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from sqlalchemy.orm import Session
import logging
from app.services.websocket_manager import ws_manager
from app.services.auth_service import verify_token
from app.database import get_db
from app.models.user import User

router = APIRouter()
logger = logging.getLogger(__name__)


async def get_user_from_token(token: str, db: Session) -> User:
    """Authenticate user from WebSocket token."""
    payload = verify_token(token)
    if not payload:
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    user = db.query(User).filter(User.id == user_id).first()
    return user


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    db: Session = Depends(get_db)
):
    """
    WebSocket endpoint for real-time updates.
    No authentication required - open to all network users.
    """
    # Accept connection (using a default user ID of 1 for everyone)
    await ws_manager.connect(websocket, 1)
    logger.info("WebSocket connection established")

    # Send welcome message
    await ws_manager.send_personal_message({
        "type": "connection_established",
        "data": {
            "message": "Connected to Network Device Mapper"
        }
    }, 1)

    try:
        # Keep connection alive and handle incoming messages
        while True:
            data = await websocket.receive_text()
            logger.debug(f"Received WebSocket message: {data}")

            # Echo back or handle client messages if needed
            # For now, we just keep the connection alive
            # Client messages can be used for ping/pong or commands

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, 1)
        logger.info("WebSocket disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket, 1)


# Callback function for scan orchestrator to send updates
async def websocket_callback(message: dict):
    """
    Callback function for scan orchestrator to broadcast messages.

    Can be called from anywhere in the application to send WebSocket updates.
    """
    # Broadcast to all connected users
    # In production, you might want to filter by user_id if message contains it
    await ws_manager.broadcast(message)
