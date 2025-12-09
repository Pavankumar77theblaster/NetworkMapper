// WebSocket Client for Real-Time Updates

class WebSocketClient {
    constructor() {
        this.ws = null;
        this.subscribers = {};
        this.reconnectInterval = 5000;
        this.isConnecting = false;
        this.shouldReconnect = true;
    }

    connect() {
        if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
            console.log('WebSocket already connected or connecting');
            return;
        }

        this.isConnecting = true;
        const wsUrl = CONFIG.WS_URL;  // No token required

        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.isConnecting = false;
                this.notifyConnectionStatus(true);
            };

            this.ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    this.handleMessage(message);
                } catch (error) {
                    console.error('Failed to parse WebSocket message:', error);
                }
            };

            this.ws.onclose = () => {
                console.log('WebSocket disconnected');
                this.isConnecting = false;
                this.notifyConnectionStatus(false);

                if (this.shouldReconnect) {
                    console.log(`Reconnecting in ${this.reconnectInterval / 1000}s...`);
                    setTimeout(() => this.connect(), this.reconnectInterval);
                }
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.isConnecting = false;
            };

        } catch (error) {
            console.error('Failed to create WebSocket connection:', error);
            this.isConnecting = false;
        }
    }

    handleMessage(message) {
        const { type, data } = message;
        console.log('WebSocket message:', type, data);

        // Notify subscribers
        if (this.subscribers[type]) {
            this.subscribers[type].forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error(`Error in subscriber callback for ${type}:`, error);
                }
            });
        }

        // Notify wildcard subscribers
        if (this.subscribers['*']) {
            this.subscribers['*'].forEach(callback => {
                try {
                    callback(message);
                } catch (error) {
                    console.error('Error in wildcard subscriber callback:', error);
                }
            });
        }
    }

    subscribe(messageType, callback) {
        if (!this.subscribers[messageType]) {
            this.subscribers[messageType] = [];
        }
        this.subscribers[messageType].push(callback);
    }

    unsubscribe(messageType, callback) {
        if (this.subscribers[messageType]) {
            this.subscribers[messageType] = this.subscribers[messageType].filter(cb => cb !== callback);
        }
    }

    notifyConnectionStatus(isConnected) {
        const event = new CustomEvent('wsConnectionChange', { detail: { isConnected } });
        window.dispatchEvent(event);
    }

    disconnect() {
        this.shouldReconnect = false;
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }

    isConnected() {
        return this.ws && this.ws.readyState === WebSocket.OPEN;
    }
}

// Create global WebSocket client instance
const wsClient = new WebSocketClient();
