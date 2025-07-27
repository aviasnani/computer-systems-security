import { useState, useEffect, useCallback } from "react";
import websocketService from "../services/websocket";

/**
 * chat project
 */
export const useChat = (roomId, userId, token) => {
  const [messages, setMessages] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [currentRoom, setCurrentRoom] = useState(null);
  const [connectionError, setConnectionError] = useState(null);
  const [lastError, setLastError] = useState(null);
  const [pendingMessagesCount, setPendingMessagesCount] = useState(0);

  // Handle incoming messages
  const handleMessage = useCallback(
    (messageData) => {
      const newMessage = {
        id: messageData.id || Date.now(),
        text: messageData.content,
        sender: messageData.sender_id === userId ? "me" : "other",
        timestamp: new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        }),
      };
      setMessages((prev) => [...prev, newMessage]);
    },
    [userId]
  );

  // Handle connection status
  const handleConnectionStatus = useCallback((status) => {
    setIsConnected(status.connected);
    setConnectionError(status.error || null);

    // Update pending messages count
    if (status.connected) {
      setPendingMessagesCount(0);
    } else {
      setPendingMessagesCount(websocketService.getPendingMessagesCount());
    }
  }, []);

  // Handle room status
  const handleRoomStatus = useCallback((roomId) => {
    setCurrentRoom(roomId);
  }, []);

  // Handle errors
  const handleError = useCallback((errorData) => {
    setLastError(errorData);

    // Update pending messages count for send errors
    if (errorData.type === "send_message") {
      setPendingMessagesCount(websocketService.getPendingMessagesCount());
    }

    // Auto-clear error after 5 seconds
    setTimeout(() => {
      setLastError(null);
    }, 5000);
  }, []);

  // Setup WebSocket connection
  useEffect(() => {
    if (!userId || !token || !roomId) return;

    // Register callbacks
    websocketService.onMessage(handleMessage);
    websocketService.onConnectionStatus(handleConnectionStatus);
    websocketService.onRoomStatus(handleRoomStatus);
    websocketService.onError(handleError);

    // Connect and join room automatically
    websocketService.connect(userId, token);
    websocketService.joinRoom(roomId);

    // Cleanup
    return () => {
      websocketService.removeMessageCallback(handleMessage);
      websocketService.removeConnectionCallback(handleConnectionStatus);
      websocketService.removeRoomCallback(handleRoomStatus);
      websocketService.removeErrorCallback(handleError);
    };
  }, [
    userId,
    token,
    roomId,
    handleMessage,
    handleConnectionStatus,
    handleRoomStatus,
    handleError,
  ]);

  // Send message function
  const sendMessage = (messageContent) => {
    if (!messageContent.trim()) return;

    const result = websocketService.sendMessage(roomId, messageContent.trim());

    // Update pending messages count
    setPendingMessagesCount(websocketService.getPendingMessagesCount());

    return result;
  };

  // Retry connection function
  const retryConnection = () => {
    websocketService.retryConnection();
  };

  return {
    messages,
    isConnected,
    currentRoom,
    sendMessage,
    connectionError,
    lastError,
    pendingMessagesCount,
    retryConnection,
  };
};

export default useChat;
