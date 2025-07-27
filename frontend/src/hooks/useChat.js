import { useState, useEffect } from "react";
import websocketService from "../services/websocket";

/** chat hook*/
export const useChat = (roomId, userId, token) => {
  const [messages, setMessages] = useState([]);
  const [isConnected, setIsConnected] = useState(false);

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

  // Setup WebSocket connection
  useEffect(() => {
    if (!userId || !token || !roomId) return;

    // Register callbacks
    websocketService.onMessage(handleMessage);
    websocketService.onConnectionStatus(handleConnectionStatus);

    // Connect and join room
    websocketService.connect(userId, token);
    setTimeout(() => {
      websocketService.joinRoom(roomId);
    }, 1000);

    // Cleanup
    return () => {
      websocketService.removeMessageCallback(handleMessage);
      websocketService.removeConnectionCallback(handleConnectionStatus);
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
    sendMessage,
  };
};

export default useChat;
