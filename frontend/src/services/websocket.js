import { io } from "socket.io-client";

class WebSocketService {
  constructor() {
    this.socket = null;
    this.isConnected = false;
    this.connectionCallbacks = [];
    this.messageCallbacks = [];
    this.roomCallbacks = [];
    this.errorCallbacks = [];
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 3;
    this.currentRoom = null;
    this.pendingRoomJoin = null;
    this.reconnectTimer = null;
    this.connectionError = null;
    this.pendingMessages = [];
    this.isReconnecting = false;
  }

  /**
   * Connect to the WebSocket server
   */
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

  /**
   * Join a specific chat room
   */
  joinRoom(roomId) {
    if (this.socket && this.isConnected) {
      // Get user_id from auth data stored during connection
      const userId = this.socket.auth?.userId;
      this.socket.emit("join_room", {
        room_id: roomId,
        user_id: userId,
      });
      this.pendingRoomJoin = roomId;
    } else {
      console.error("Cannot join room: WebSocket not connected");
      // Store the room to join once connected
      this.pendingRoomJoin = roomId;
    }
  }

  /**
   * Leave a specific chat room
   */
  leaveRoom(roomId) {
    if (this.socket && this.isConnected) {
      // Get user_id from auth data stored during connection
      const userId = this.socket.auth?.userId;
      this.socket.emit("leave_room", {
        room_id: roomId,
        user_id: userId,
      });
      if (this.currentRoom === roomId) {
        this.currentRoom = null;
        this.notifyRoomStatus(null);
      }
    } else {
      console.error("Cannot leave room: WebSocket not connected");
    }
  }

  /**
   * Send a message to a room
   */
  sendMessage(roomId, message) {
    const messageData = {
      sender_id: this.socket?.auth?.userId,
      room_id: roomId,
      content: message,
      message_type: "text",
      id: Date.now() + Math.random(), // Temporary ID for tracking
      timestamp: new Date().toISOString(),
    };

    if (this.socket && this.isConnected) {
      try {
        this.socket.emit("send_message", messageData);
        return { success: true, messageId: messageData.id };
      } catch (error) {
        console.error("Failed to send message:", error);
        this.notifyError("Failed to send message", "send_message", {
          messageData,
          error: error.message,
        });
        return {
          success: false,
          error: error.message,
          messageId: messageData.id,
        };
      }
    } else {
      // Queue message for retry when reconnected
      this.pendingMessages.push(messageData);
      const errorMsg = this.isReconnecting
        ? "Reconnecting... Message will be sent when connected."
        : "WebSocket not connected";
      this.notifyError(errorMsg, "send_message", { messageData });
      return {
        success: false,
        error: errorMsg,
        messageId: messageData.id,
        queued: true,
      };
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

  /**
   * Register callback for room status changes
   */
  onRoomStatus(callback) {
    this.roomCallbacks.push(callback);
  }

  /**
   * Register callback for error notifications
   */
  onError(callback) {
    this.errorCallbacks.push(callback);
  }

  /**
   * Remove message callback
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
   * Remove room status callback
   */
  removeRoomCallback(callback) {
    this.roomCallbacks = this.roomCallbacks.filter((cb) => cb !== callback);
  }

  /**
   * Remove error callback
   */
  removeErrorCallback(callback) {
    this.errorCallbacks = this.errorCallbacks.filter((cb) => cb !== callback);
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
      this.isReconnecting = false;
      this.reconnectAttempts = 0;
      this.connectionError = null;

      // Clear any existing reconnect timer
      if (this.reconnectTimer) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
      }

      this.notifyConnectionStatus(true);

      // Auto-join pending room if any
      if (this.pendingRoomJoin) {
        setTimeout(() => {
          this.joinRoom(this.pendingRoomJoin);
        }, 100);
      }

      // Send any pending messages
      this.sendPendingMessages();
    });

    // Connection lost
    this.socket.on("disconnect", (reason) => {
      console.log("WebSocket disconnected:", reason);
      this.isConnected = false;
      this.connectionError = `Disconnected: ${reason}`;
      this.notifyConnectionStatus(false, this.connectionError);

      // Attempt reconnection if not manually disconnected
      if (reason !== "io client disconnect") {
        this.isReconnecting = true;
        this.attemptReconnection();
      }
    });

    // Connection error
    this.socket.on("connect_error", (error) => {
      console.error("WebSocket connection error:", error);
      this.isConnected = false;
      this.connectionError = error.message || "Connection failed";
      this.notifyConnectionStatus(false, this.connectionError);
      this.notifyError("Connection failed", "connect_error", {
        error: error.message,
      });

      if (!this.isReconnecting) {
        this.isReconnecting = true;
        this.attemptReconnection();
      }
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
      this.currentRoom = data.room_id;
      this.pendingRoomJoin = null;
      this.notifyRoomStatus(data.room_id);
    });

    // Room left confirmation
    this.socket.on("room_left", (data) => {
      console.log("Left room:", data.room_id);
      if (this.currentRoom === data.room_id) {
        this.currentRoom = null;
        this.notifyRoomStatus(null);
      }
    });

    // Message sent confirmation
    this.socket.on("message_sent", (data) => {
      console.log("Message sent successfully:", data);
    });

    // Room join error handling
    this.socket.on("room_join_error", (data) => {
      console.error("Room join error:", data.message);
      this.pendingRoomJoin = null;
    });

    // Room leave error handling
    this.socket.on("room_leave_error", (data) => {
      console.error("Room leave error:", data.message);
    });

    // Message error handling
    this.socket.on("message_error", (data) => {
      console.error("Message error:", data.message);
      this.notifyError("Message failed to send", "message_error", data);
    });
  }

  /**
   * Attempt to reconnect to the server
   */
  attemptReconnection() {
    // Clear any existing timer
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error("Max reconnection attempts reached");
      this.isReconnecting = false;
      this.connectionError =
        "Max reconnection attempts reached. Please refresh the page.";
      this.notifyConnectionStatus(false, this.connectionError);
      this.notifyError(
        "Connection failed permanently",
        "max_reconnect_attempts",
        {
          attempts: this.reconnectAttempts,
          maxAttempts: this.maxReconnectAttempts,
        }
      );
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(Math.pow(2, this.reconnectAttempts) * 1000, 30000); // Exponential backoff, max 30s

    console.log(
      `Attempting reconnection ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`
    );

    this.connectionError = `Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`;
    this.notifyConnectionStatus(false, this.connectionError);

    this.reconnectTimer = setTimeout(() => {
      if (this.socket && !this.isConnected) {
        try {
          this.socket.connect();
        } catch (error) {
          console.error("Reconnection attempt failed:", error);
          this.attemptReconnection(); // Try again
        }
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

  /**
   * Get current rooms
   */
  getCurrentRoom() {
    return this.currentRoom;
  }

  /**
   * Notify all room status callbacks
   */
  notifyRoomStatus(roomId) {
    this.roomCallbacks.forEach((callback) => {
      try {
        callback(roomId);
      } catch (error) {
        console.error("Error in room status callback:", error);
      }
    });
  }

  /**
   * Notify all error callbacks
   */
  notifyError(message, type, details = {}) {
    const errorData = {
      message,
      type,
      details,
      timestamp: new Date().toISOString(),
    };

    this.errorCallbacks.forEach((callback) => {
      try {
        callback(errorData);
      } catch (error) {
        console.error("Error in error callback:", error);
      }
    });
  }

  /**
   * Send any pending messages that were queued during disconnection
   */
  sendPendingMessages() {
    if (this.pendingMessages.length === 0) return;

    console.log(`Sending ${this.pendingMessages.length} pending messages`);
    const messagesToSend = [...this.pendingMessages];
    this.pendingMessages = [];

    messagesToSend.forEach((messageData) => {
      try {
        this.socket.emit("send_message", messageData);
      } catch (error) {
        console.error("Failed to send pending message:", error);
        // Re-queue the message if it fails
        this.pendingMessages.push(messageData);
        this.notifyError(
          "Failed to send queued message",
          "send_pending_message",
          { messageData, error: error.message }
        );
      }
    });
  }

  /**
   * Manually retry connection
   */
  retryConnection() {
    if (this.isConnected) {
      console.log("Already connected");
      return;
    }

    // Reset reconnection attempts to allow manual retry
    this.reconnectAttempts = 0;
    this.isReconnecting = true;
    this.connectionError = "Retrying connection...";
    this.notifyConnectionStatus(false, this.connectionError);

    if (this.socket) {
      try {
        this.socket.connect();
      } catch (error) {
        console.error("Manual retry failed:", error);
        this.attemptReconnection();
      }
    }
  }

  /**
   * Get current connection error
   */
  getConnectionError() {
    return this.connectionError;
  }

  /**
   * Get pending messages count
   */
  getPendingMessagesCount() {
    return this.pendingMessages.length;
  }
}

const websocketService = new WebSocketService();
export default websocketService;
