import { io } from "socket.io-client";

class WebSocketService {
  constructor() {
    this.socket = null;
    this.isConnected = false;
    this.connectionCallbacks = [];
    this.messageCallbacks = [];
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 3;
  }

  // Connect to the WebSocket server

  connect(userId, token) {
    if (this.socket && this.isConnected) {
      console.log("WebSocket already connected");
      return;
    }

    // Get server URL from environment or default to localhost
    const serverUrl =
      process.env.NEXT_PUBLIC_WEBSOCKET_URL || "http://localhost:5000";

    this.socket = io(serverUrl, {
      auth: {
        userId,
        token,
      },
      transports: ["websocket", "polling"],
      timeout: 20000,
    });

    this.setupEventListeners();
  }

  /**
   * Disconnect from the WebSocket server
   */
  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.isConnected = false;
      this.reconnectAttempts = 0;
      this.notifyConnectionStatus(false);
    }
  }

  // Join a specific chat room

  joinRoom(roomId) {
    if (this.socket && this.isConnected) {
      this.socket.emit("join_room", { room_id: roomId });
    } else {
      console.error("Cannot join room: WebSocket not connected");
    }
  }

  leaveRoom(roomId) {
    if (this.socket && this.isConnected) {
      this.socket.emit("leave_room", { room_id: roomId });
    } else {
      console.error("Cannot leave room: WebSocket not connected");
    }
  }

  sendMessage(roomId, message) {
    if (this.socket && this.isConnected) {
      this.socket.emit("send_message", {
        room_id: roomId,
        content: message,
        message_type: "text",
      });
    } else {
      console.error("Cannot send message: WebSocket not connected");
      throw new Error("WebSocket not connected");
    }
  }

  /**
   * Register callback for incoming messages
   */
  onMessage(callback) {
    this.messageCallbacks.push(callback);
  }

  /**
   * Register callback for connection status changes
   */
  onConnectionStatus(callback) {
    this.connectionCallbacks.push(callback);
  }

  /** Remove message callback
   */
  removeMessageCallback(callback) {
    this.messageCallbacks = this.messageCallbacks.filter(
      (cb) => cb !== callback
    );
  }

  /**
   * Remove connection status callback
   */
  removeConnectionCallback(callback) {
    this.connectionCallbacks = this.connectionCallbacks.filter(
      (cb) => cb !== callback
    );
  }

  /**
   * Setup event listeners for the socket
   */
  setupEventListeners() {
    if (!this.socket) return;

    // Connection established
    this.socket.on("connect", () => {
      console.log("WebSocket connected");
      this.isConnected = true;
      this.reconnectAttempts = 0;
      this.notifyConnectionStatus(true);
    });

    // Connection lost
    this.socket.on("disconnect", (reason) => {
      console.log("WebSocket disconnected:", reason);
      this.isConnected = false;
      this.notifyConnectionStatus(false);

      // Attempt reconnection if not manually disconnected
      if (reason !== "io client disconnect") {
        this.attemptReconnection();
      }
    });

    // Connection error
    this.socket.on("connect_error", (error) => {
      console.error("WebSocket connection error:", error);
      this.isConnected = false;
      this.notifyConnectionStatus(false, error.message);
      this.attemptReconnection();
    });

    // Incoming messages
    this.socket.on("new_message", (messageData) => {
      this.messageCallbacks.forEach((callback) => {
        try {
          callback(messageData);
        } catch (error) {
          console.error("Error in message callback:", error);
        }
      });
    });

    // Room joined confirmation
    this.socket.on("room_joined", (data) => {
      console.log("Joined room:", data.room_id);
    });

    // Room left confirmation
    this.socket.on("room_left", (data) => {
      console.log("Left room:", data.room_id);
    });

    // Message sent confirmation
    this.socket.on("message_sent", (data) => {
      console.log("Message sent successfully:", data);
    });
  }

  /**
   * Attempt to reconnect to the server
   */
  attemptReconnection() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error("Max reconnection attempts reached");
      this.notifyConnectionStatus(false, "Max reconnection attempts reached");
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.pow(2, this.reconnectAttempts) * 1000; // Exponential backoff

    console.log(
      `Attempting reconnection ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`
    );

    setTimeout(() => {
      if (this.socket && !this.isConnected) {
        this.socket.connect();
      }
    }, delay);
  }

  /**
   * Notify all connection status callbacks
   */
  notifyConnectionStatus(connected, error = null) {
    this.connectionCallbacks.forEach((callback) => {
      try {
        callback({ connected, error });
      } catch (error) {
        console.error("Error in connection status callback:", error);
      }
    });
  }

  /**
   * Get current connection status
   */
  getConnectionStatus() {
    return this.isConnected;
  }
}

const websocketService = new WebSocketService();
export default websocketService;
