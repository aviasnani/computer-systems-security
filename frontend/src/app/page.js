"use client";
import React, { useState, useRef, useEffect } from "react";
import Login from "./components/Login";
import { useAuth } from "../context/AuthContext";
import { useChat } from "../hooks/useChat";

export default function ChatApp() {
  const { currentUser, loading } = useAuth();

  // Default room for this implementation
  const defaultRoomId = "general";

  // Use WebSocket chat hook
  const {
    messages,
    isConnected,
    currentRoom,
    sendMessage: sendWebSocketMessage,
    connectionError,
    lastError,
    pendingMessagesCount,
    retryConnection,
  } = useChat(defaultRoomId, currentUser?.uid, currentUser?.accessToken);

  const [messageInput, setMessageInput] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const messageEndRef = useRef(null);

  // Static conversations for sidebar (will be replaced in future tasks)
  const [conversations] = useState([
    {
      id: 1,
      name: "General Chat",
      lastMessage: "Welcome to the chat!",
      timestamp: new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
      unread: 0,
      online: true,
      isGroup: true,
      roomId: defaultRoomId,
    },
  ]);

  const [activeChat, setActiveChat] = useState(1);
  const currentConversation = conversations.find(
    (conv) => conv.id === activeChat
  );

  useEffect(() => {
    messageEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = () => {
    if (messageInput.trim()) {
      const result = sendWebSocketMessage(messageInput);
      if (result?.success || result?.queued) {
        setMessageInput("");
      }
      // Error handling is now managed by the hook and displayed in UI
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const filteredConversations = conversations.filter((conv) =>
    conv.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (loading) {
    return (
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          height: "100vh",
        }}
      >
        <div>Loading...</div>
      </div>
    );
  }

  if (!currentUser) {
    return <Login />;
  }

  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        fontFamily: "Arial, sans-serif",
        backgroundColor: "#292828",
      }}
    >
      {/* Sidebar */}
      <div
        style={{
          width: "300px",
          borderRight: "1px solid #ccc",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* User Profile Section */}
        <div style={{ padding: "20px", borderBottom: "1px solid #eee" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div
              style={{
                width: "40px",
                height: "40px",
                borderRadius: "50%",
                backgroundColor: "#007bff",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "white",
              }}
            >
              ME
            </div>
            <div>
              <div style={{ fontWeight: "bold" }}>My Profile</div>
            </div>
          </div>
        </div>

        {/* Search */}
        <div style={{ padding: "10px" }}>
          <input
            type="text"
            placeholder="Search conversations..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: "100%",
              padding: "8px",
              border: "1px solid #ccc",
              borderRadius: "4px",
            }}
          />
        </div>

        {/* Conversations List */}
        <div style={{ flex: 1, overflowY: "auto" }}>
          {filteredConversations.map((conv) => (
            <div
              key={conv.id}
              onClick={() => setActiveChat(conv.id)}
              style={{
                padding: "15px",
                borderBottom: "1px solid #eee",
                cursor: "pointer",
                backgroundColor:
                  activeChat === conv.id ? "#f0f8ff" : "transparent",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", gap: "10px" }}
              >
                <div style={{ position: "relative" }}>
                  <div
                    style={{
                      width: "40px",
                      height: "40px",
                      borderRadius: "50%",
                      backgroundColor: "#28a745",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: "white",
                    }}
                  >
                    {conv.isGroup
                      ? "👥"
                      : conv.name
                          .split(" ")
                          .map((n) => n[0])
                          .join("")}
                  </div>
                  {conv.online && (
                    <div
                      style={{
                        position: "absolute",
                        bottom: "0",
                        right: "0",
                        width: "12px",
                        height: "12px",
                        borderRadius: "50%",
                        backgroundColor: "#28a745",
                        border: "2px solid white",
                      }}
                    ></div>
                  )}
                </div>
                <div style={{ flex: 1 }}>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <span style={{ fontWeight: "bold" }}>{conv.name}</span>
                    <span style={{ fontSize: "12px", color: "#666" }}>
                      {conv.timestamp}
                    </span>
                  </div>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <span
                      style={{
                        fontSize: "14px",
                        color: "#666",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {conv.lastMessage}
                    </span>
                    {conv.unread > 0 && (
                      <span
                        style={{
                          backgroundColor: "#dc3545",
                          color: "white",
                          borderRadius: "50%",
                          width: "20px",
                          height: "20px",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontSize: "12px",
                        }}
                      >
                        {conv.unread}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Main Chat Area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        {currentConversation ? (
          <>
            {/* Chat Header */}
            <div
              style={{
                padding: "15px",
                borderBottom: "1px solid #ccc",
                display: "flex",
                alignItems: "center",
                gap: "10px",
                justifyContent: "space-between",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", gap: "10px" }}
              >
                <div
                  style={{
                    width: "40px",
                    height: "40px",
                    borderRadius: "50%",
                    backgroundColor: "#28a745",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    color: "white",
                  }}
                >
                  {currentConversation.isGroup
                    ? "👥"
                    : currentConversation.name
                        .split(" ")
                        .map((n) => n[0])
                        .join("")}
                </div>
                <div>
                  <div style={{ fontWeight: "bold" }}>
                    {currentConversation.name}
                  </div>
                  {currentRoom && (
                    <div style={{ fontSize: "12px", color: "#666" }}>
                      Room: {currentRoom}
                    </div>
                  )}
                </div>
              </div>

              {/* Connection and Room Status */}
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "flex-end",
                  gap: "2px",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: "5px" }}
                >
                  <div
                    style={{
                      width: "8px",
                      height: "8px",
                      borderRadius: "50%",
                      backgroundColor: isConnected ? "#28a745" : "#dc3545",
                    }}
                  ></div>
                  <span
                    style={{
                      fontSize: "12px",
                      color: isConnected ? "#28a745" : "#dc3545",
                    }}
                  >
                    {isConnected
                      ? "Connected"
                      : connectionError || "Disconnected"}
                  </span>
                  {!isConnected && (
                    <button
                      onClick={retryConnection}
                      style={{
                        fontSize: "10px",
                        padding: "2px 6px",
                        backgroundColor: "#007bff",
                        color: "white",
                        border: "none",
                        borderRadius: "3px",
                        cursor: "pointer",
                        marginLeft: "5px",
                      }}
                    >
                      Retry
                    </button>
                  )}
                </div>
                {currentRoom && isConnected && (
                  <div style={{ fontSize: "11px", color: "#666" }}>
                    Joined: {currentRoom}
                  </div>
                )}
                {pendingMessagesCount > 0 && (
                  <div style={{ fontSize: "10px", color: "#ffc107" }}>
                    {pendingMessagesCount} message
                    {pendingMessagesCount > 1 ? "s" : ""} queued
                  </div>
                )}
              </div>
            </div>

            {/* Messages Area */}
            <div style={{ flex: 1, overflowY: "auto", padding: "10px" }}>
              {messages.length === 0 ? (
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    height: "100%",
                    color: "#666",
                    flexDirection: "column",
                    gap: "10px",
                  }}
                >
                  {isConnected ? (
                    <>
                      <div>No messages yet. Start the conversation!</div>
                      {currentRoom && (
                        <div style={{ fontSize: "14px", color: "#999" }}>
                          You&apos;re in room: <strong>{currentRoom}</strong>
                        </div>
                      )}
                    </>
                  ) : (
                    <div>Connecting to chat...</div>
                  )}
                </div>
              ) : (
                messages.map((message) => (
                  <div
                    key={message.id}
                    style={{
                      display: "flex",
                      justifyContent:
                        message.sender === "me" ? "flex-end" : "flex-start",
                      marginBottom: "10px",
                    }}
                  >
                    <div
                      style={{
                        maxWidth: "70%",
                        padding: "10px",
                        borderRadius: "10px",
                        backgroundColor:
                          message.sender === "me" ? "#007bff" : "#f1f1f1",
                        color: message.sender === "me" ? "white" : "black",
                      }}
                    >
                      {message.senderName && (
                        <div
                          style={{
                            fontSize: "12px",
                            fontWeight: "bold",
                            marginBottom: "5px",
                          }}
                        >
                          {message.senderName}
                        </div>
                      )}
                      <div>{message.text}</div>
                      <div
                        style={{
                          fontSize: "11px",
                          opacity: 0.7,
                          marginTop: "5px",
                        }}
                      >
                        {message.timestamp}
                        {message.sender === "me" && (
                          <span style={{ marginLeft: "5px" }}>✓✓</span>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
              <div ref={messageEndRef} />
            </div>

            {/* Message Input Area */}
            <div style={{ padding: "15px", borderTop: "1px solid #ccc" }}>
              {/* Connection Error Display */}
              {!isConnected && (
                <div
                  style={{
                    padding: "8px",
                    backgroundColor: "#fff3cd",
                    border: "1px solid #ffeaa7",
                    borderRadius: "4px",
                    marginBottom: "10px",
                    fontSize: "14px",
                    color: "#856404",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <span>
                    {connectionError || "Disconnected from chat"}
                    {pendingMessagesCount > 0 && (
                      <span style={{ marginLeft: "10px", fontSize: "12px" }}>
                        ({pendingMessagesCount} message
                        {pendingMessagesCount > 1 ? "s" : ""} will be sent when
                        reconnected)
                      </span>
                    )}
                  </span>
                  <button
                    onClick={retryConnection}
                    style={{
                      fontSize: "12px",
                      padding: "4px 8px",
                      backgroundColor: "#007bff",
                      color: "white",
                      border: "none",
                      borderRadius: "3px",
                      cursor: "pointer",
                    }}
                  >
                    Retry Now
                  </button>
                </div>
              )}

              {/* Last Error Display */}
              {lastError && (
                <div
                  style={{
                    padding: "8px",
                    backgroundColor: "#f8d7da",
                    border: "1px solid #f5c6cb",
                    borderRadius: "4px",
                    marginBottom: "10px",
                    fontSize: "14px",
                    color: "#721c24",
                  }}
                >
                  {lastError.message}
                  {lastError.type === "send_message" &&
                    lastError.details?.queued && (
                      <span style={{ fontSize: "12px", marginLeft: "10px" }}>
                        (Message queued for retry)
                      </span>
                    )}
                </div>
              )}

              <div
                style={{ display: "flex", gap: "10px", alignItems: "flex-end" }}
              >
                <textarea
                  value={messageInput}
                  onChange={(e) => setMessageInput(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder={
                    isConnected ? "Type a message..." : "Connecting to chat..."
                  }
                  disabled={!isConnected}
                  style={{
                    flex: 1,
                    padding: "10px",
                    border: "1px solid #ccc",
                    borderRadius: "4px",
                    resize: "none",
                    minHeight: "40px",
                    maxHeight: "100px",
                    backgroundColor: isConnected ? "white" : "#f8f9fa",
                    opacity: isConnected ? 1 : 0.7,
                  }}
                  rows={1}
                />

                <button
                  onClick={sendMessage}
                  disabled={!messageInput.trim()}
                  style={{
                    padding: "10px 20px",
                    backgroundColor: !messageInput.trim()
                      ? "#6c757d"
                      : isConnected
                      ? "#007bff"
                      : "#ffc107",
                    color: "white",
                    border: "none",
                    borderRadius: "4px",
                    cursor: !messageInput.trim() ? "not-allowed" : "pointer",
                  }}
                  title={
                    !isConnected
                      ? "Message will be queued and sent when reconnected"
                      : "Send message"
                  }
                >
                  {isConnected ? "Send" : "Queue"}
                </button>
              </div>
            </div>
          </>
        ) : (
          <div
            style={{
              flex: 1,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "#666",
            }}
          >
            Select a conversation to start chatting
          </div>
        )}
      </div>

      {/* Settings Panel */}
      {showSettings && (
        <div
          style={{
            position: "absolute",
            top: "80px",
            left: "20px",
            width: "250px",
            backgroundColor: "white",
            border: "1px solid #ccc",
            borderRadius: "4px",
            padding: "15px",
            boxShadow: "0 2px 10px rgba(0,0,0,0.1)",
          }}
        >
          <h3>Settings</h3>
          <div style={{ marginBottom: "10px" }}>
            <label>
              <input type="checkbox" /> Notifications
            </label>
          </div>
          <div style={{ marginBottom: "10px" }}>
            <label>
              <input type="checkbox" /> Sound
            </label>
          </div>
          <div style={{ marginBottom: "10px" }}>
            <label>Theme:</label>
            <select style={{ marginLeft: "5px" }}>
              <option>Light</option>
              <option>Dark</option>
            </select>
          </div>
          <button onClick={() => setShowSettings(false)}>Close</button>
        </div>
      )}
    </div>
  );
}
