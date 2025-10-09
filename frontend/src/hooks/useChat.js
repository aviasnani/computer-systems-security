import { useState, useEffect, useCallback } from "react";
import websocketService from "../services/websocket";
import CryptoService from "../services/cryptoService";

/**
 * Enhanced chat hook with end-to-end encryption support
 */
export const useChat = (roomId, userId, token, rsaKeys) => {
  const [messages, setMessages] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [currentRoom, setCurrentRoom] = useState(null);
  const [connectionError, setConnectionError] = useState(null);
  const [lastError, setLastError] = useState(null);
  const [pendingMessagesCount, setPendingMessagesCount] = useState(0);
  const [recipientKeys, setRecipientKeys] = useState({});
  const [isLoadingKeys, setIsLoadingKeys] = useState(false);

  // Fetch public keys for users in the room
  const fetchRecipientKeys = useCallback(async () => {
    if (!roomId || !token) return;
    
    setIsLoadingKeys(true);
    try {
      // Get online users (in a real app, you'd get users in the specific room)
      const response = await fetch("http://localhost:5001/api/users/online", {
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'success') {
          // Fetch public keys for all online users
          const userIds = data.data.online_users.map(user => user.user_id);
          
          if (userIds.length > 0) {
            const keysResponse = await fetch("http://localhost:5001/api/users/batch-keys", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
              },
              body: JSON.stringify({ user_ids: userIds })
            });
            
            if (keysResponse.ok) {
              const keysData = await keysResponse.json();
              if (keysData.status === 'success') {
                const keys = {};
                Object.entries(keysData.data).forEach(([userId, keyInfo]) => {
                  keys[userId] = keyInfo.public_key;
                });
                setRecipientKeys(keys);
                console.log('Loaded recipient keys:', Object.keys(keys).length);
              }
            }
          }
        }
      }
    } catch (error) {
      console.error('Failed to fetch recipient keys:', error);
    } finally {
      setIsLoadingKeys(false);
    }
  }, [roomId, token]);

  // Handle incoming messages with decryption
  const handleMessage = useCallback(
    async (messageData) => {
      console.log('Received message:', messageData);
      let content = messageData.content;

      // Try to decrypt if it's encrypted
      if (messageData.is_encrypted && rsaKeys?.privateKey) {
        try {
          const encryptedMessage = {
            encryptedContent: messageData.content,
            iv: messageData.iv,
            encryptedAesKeys: JSON.parse(messageData.encrypted_aes_key || '{}'),
            encryptionType: messageData.encryption_type
          };
          
          content = await CryptoService.decryptMessage(encryptedMessage, rsaKeys.privateKey);
          console.log('Decrypted message:', content);
        } catch (e) {
          console.error('Decryption failed:', e);
          content = '[Encrypted message - cannot decrypt]';
        }
      } else if (content.startsWith("{")) {
        // Legacy format - try to decrypt with AES
        try {
          const encrypted = JSON.parse(content);
          if (encrypted.encryptedData && encrypted.iv) {
            // This would need the AES key to decrypt
            content = '[Legacy encrypted message]';
          }
        } catch (e) {
          console.log('Not a legacy encrypted message');
        }
      }

      const newMessage = {
        id: messageData.message_id || messageData.id || Date.now(),
        text: content,
        sender: messageData.sender_id === userId ? "me" : "other",
        timestamp: new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        }),
        isEncrypted: messageData.is_encrypted || false,
      };
      console.log('Adding message to UI:', newMessage);
      setMessages((prev) => [...prev, newMessage]);
    },
    [userId, rsaKeys]
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

    // Fetch recipient keys when joining room
    fetchRecipientKeys();

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
    fetchRecipientKeys,
  ]);

  // Send encrypted message function
  const sendMessage = async (messageContent) => {
    if (!messageContent.trim()) return;

    let encryptedContent = messageContent;
    let encryptionData = null;

    // Encrypt message if we have recipient keys and RSA keys
    if (Object.keys(recipientKeys).length > 0 && rsaKeys?.privateKey) {
      try {
        const encrypted = await CryptoService.encryptMessageForRecipients(
          messageContent,
          recipientKeys
        );
        
        encryptedContent = encrypted.encryptedContent;
        encryptionData = {
          is_encrypted: true,
          encryption_type: encrypted.encryptionType,
          encrypted_aes_key: JSON.stringify(encrypted.encryptedAesKeys),
          iv: encrypted.iv
        };
        
        console.log('Message encrypted for', Object.keys(recipientKeys).length, 'recipients');
      } catch (error) {
        console.error('Encryption failed:', error);
        // Fall back to plain text
      }
    }

    const result = websocketService.sendMessage(roomId, encryptedContent, encryptionData);

    // Update pending messages count
    setPendingMessagesCount(websocketService.getPendingMessagesCount());

    return result;
  };

  // Retry connection function
  const retryConnection = () => {
    websocketService.retryConnection();
  };

  // Refresh recipient keys
  const refreshKeys = () => {
    fetchRecipientKeys();
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
    recipientKeys,
    isLoadingKeys,
    refreshKeys,
  };
};

export default useChat;
