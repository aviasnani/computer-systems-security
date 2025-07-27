import { useState, useEffect } from "react";
import websocketService from "../services/websocket";

/**
 * chat project
 */
export const useChat = (roomId, userId, token) => {
  const [messages, setMessages] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [currentRoom, setCurrentRoom] = useState(null);

  // Handle incoming messages
  const handleMessage = (messageData) => {
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
  };

  // Handle connection status
  const handleConnectionStatus = (status) => {
    setIsConnected(status.connected);
  };

  // Handle room status
  const handleRoomStatus = (roomId) => {
    setCurrentRoom(roomId);
  };

  // Setup WebSocket connection
  useEffect(() => {
    if (!userId || !token || !roomId) return;

    // Register callbacks
    websocketService.onMessage(handleMessage);
    websocketService.onConnectionStatus(handleConnectionStatus);
    websocketService.onRoomStatus(handleRoomStatus);

    // Connect and join room automatically
    websocketService.connect(userId, token);
    websocketService.joinRoom(roomId);

    // Cleanup
    return () => {
      websocketService.removeMessageCallback(handleMessage);
      websocketService.removeConnectionCallback(handleConnectionStatus);
      websocketService.removeRoomCallback(handleRoomStatus);
    };
  }, [userId, token, roomId]);

  // Send message function
  const sendMessage = (messageContent) => {
    if (!messageContent.trim() || !isConnected) return;

    websocketService.sendMessage(roomId, messageContent.trim());
  };

  return {
    messages,
    isConnected,
    currentRoom,
    sendMessage,
  };
};

export default useChat;
