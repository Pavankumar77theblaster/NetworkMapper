"""WebSocket connection manager for real-time updates."""
import logging
from typing import Dict, List
from fastapi import WebSocket
import json

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket connections and broadcasts messages."""

    def __init__(self):
        # Store active connections: user_id -> list of WebSocket connections
        self.active_connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        """Accept and store a new WebSocket connection."""
        await websocket.accept()

        if user_id not in self.active_connections:
            self.active_connections[user_id] = []

        self.active_connections[user_id].append(websocket)
        logger.info(f"WebSocket connected for user {user_id}. Total connections: {len(self.active_connections[user_id])}")

    def disconnect(self, websocket: WebSocket, user_id: int):
        """Remove a WebSocket connection."""
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
                logger.info(f"WebSocket disconnected for user {user_id}. Remaining connections: {len(self.active_connections[user_id])}")

            # Clean up empty user entries
            if len(self.active_connections[user_id]) == 0:
                del self.active_connections[user_id]

    async def send_personal_message(self, message: dict, user_id: int):
        """Send a message to all connections of a specific user."""
        if user_id in self.active_connections:
            message_json = json.dumps(message)

            # Send to all connections for this user
            dead_connections = []
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_text(message_json)
                except Exception as e:
                    logger.error(f"Failed to send message to user {user_id}: {e}")
                    dead_connections.append(connection)

            # Remove dead connections
            for dead_conn in dead_connections:
                self.disconnect(dead_conn, user_id)

    async def broadcast(self, message: dict):
        """Broadcast a message to all connected users."""
        message_json = json.dumps(message)
        dead_connections = []

        for user_id, connections in self.active_connections.items():
            for connection in connections:
                try:
                    await connection.send_text(message_json)
                except Exception as e:
                    logger.error(f"Failed to broadcast to user {user_id}: {e}")
                    dead_connections.append((connection, user_id))

        # Remove dead connections
        for dead_conn, user_id in dead_connections:
            self.disconnect(dead_conn, user_id)

    async def broadcast_to_user(self, message: dict, user_id: int):
        """Broadcast a message to a specific user (alias for send_personal_message)."""
        await self.send_personal_message(message, user_id)

    def get_connection_count(self, user_id: int = None) -> int:
        """Get the number of active connections (for a user or total)."""
        if user_id:
            return len(self.active_connections.get(user_id, []))
        else:
            return sum(len(conns) for conns in self.active_connections.values())


# Global WebSocket manager instance
ws_manager = WebSocketManager()
