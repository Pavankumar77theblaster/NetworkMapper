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
    token: str = Query(...),
    db: Session = Depends(get_db)
):
    """
    WebSocket endpoint for real-time updates.

    Authenticates via JWT token in query parameter: /ws?token=xxx
    """
    # Authenticate user
    user = await get_user_from_token(token, db)
    if not user:
        await websocket.close(code=1008, reason="Unauthorized")
        logger.warning("WebSocket connection rejected: Invalid token")
        return

    if not user.is_active:
        await websocket.close(code=1008, reason="Inactive user")
        logger.warning(f"WebSocket connection rejected: User {user.id} is inactive")
        return

    # Accept connection
    await ws_manager.connect(websocket, user.id)
    logger.info(f"WebSocket connection established for user {user.id}")

    # Send welcome message
    await ws_manager.send_personal_message({
        "type": "connection_established",
        "data": {
            "message": "Connected to Network Device Mapper",
            "user_id": user.id,
            "username": user.username
        }
    }, user.id)

    try:
        # Keep connection alive and handle incoming messages
        while True:
            data = await websocket.receive_text()
            logger.debug(f"Received WebSocket message from user {user.id}: {data}")

            # Echo back or handle client messages if needed
            # For now, we just keep the connection alive
            # Client messages can be used for ping/pong or commands

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, user.id)
        logger.info(f"WebSocket disconnected for user {user.id}")
    except Exception as e:
        logger.error(f"WebSocket error for user {user.id}: {e}")
        ws_manager.disconnect(websocket, user.id)


# Callback function for scan orchestrator to send updates
async def websocket_callback(message: dict):
    """
    Callback function for scan orchestrator to broadcast messages.

    Can be called from anywhere in the application to send WebSocket updates.
    """
    # Broadcast to all connected users
    # In production, you might want to filter by user_id if message contains it
    await ws_manager.broadcast(message)
