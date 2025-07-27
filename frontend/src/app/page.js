"use client";
import React, { useState, useRef, useEffect } from "react";
import Login from "./components/Login";
import { useAuth } from "../context/AuthContext";
import { useChat } from "../hooks/useChat";
import { useKeyManagement } from "../hooks/useKeyManagement";
import CryptoService from "../services/cryptoService";

export default function ChatApp() {
  const { currentUser, loading } = useAuth();
  const { rsaKeys, aesKey, isGenerating } = useKeyManagement(currentUser?.uid);
  // --- UI State ---
  const [friends, setFriends] = useState([
    // Example friend list
    { id: 2, name: "Alice", online: true },
    { id: 3, name: "Bob", online: false },
  ]);
  const [rooms, setRooms] = useState([
    // Example room list
    { id: "general", name: "General Chat" },
  ]);
  const [showAddFriend, setShowAddFriend] = useState(false);
  const [addFriendEmail, setAddFriendEmail] = useState("");
  const [activeRoom, setActiveRoom] = useState(null); // No room joined by default
  const [messageInput, setMessageInput] = useState("");
  const messageEndRef = useRef(null);

  // Only join/use chat when a room is selected
  const chat = activeRoom
    ? useChat(activeRoom.id, currentUser?.uid, 'mock-token', aesKey)
    : {};
  const {
    messages = [],
    isConnected = false,
    currentRoom = null,
    sendMessage: sendWebSocketMessage = () => {},
    connectionError = null,
    lastError = null,
    pendingMessagesCount = 0,
    retryConnection = () => {},
  } = chat;

  useEffect(() => {
    messageEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = async () => {
    if (messageInput.trim() && activeRoom) {
      let messageToSend = messageInput.trim();
      if (aesKey) {
        try {
          const encrypted = await CryptoService.encryptWithAES(
            messageToSend,
            aesKey
          );
          messageToSend = JSON.stringify(encrypted);
        } catch (error) {
          console.error("Encryption failed:", error);
        }
      }
      const result = sendWebSocketMessage(messageToSend);
      if (result?.success || result?.queued) {
        setMessageInput("");
      }
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  // Add friend handler (stub)
  const handleAddFriend = () => {
    if (addFriendEmail.trim()) {
      setFriends((prev) => [
        ...prev,
        { id: Date.now(), name: addFriendEmail, online: false },
      ]);
      setAddFriendEmail("");
      setShowAddFriend(false);
    }
  };

  if (loading || isGenerating) {
    return (
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          height: "100vh",
          backgroundColor: "#1a1a1a",
          color: "white",
        }}
      >
        <div style={{ textAlign: "center" }}>
          <div
            style={{
              width: "40px",
              height: "40px",
              border: "4px solid #333",
              borderTop: "4px solid #007bff",
              borderRadius: "50%",
              animation: "spin 1s linear infinite",
              margin: "0 auto 20px",
            }}
          ></div>
          <div>{loading ? "Loading..." : "Generating encryption keys..."}</div>
        </div>
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
        backgroundColor: "#18181b",
        color: "#fff",
        fontFamily: "Inter, Arial, sans-serif",
      }}
    >
      {/* Sidebar */}
      <div
        style={{
          width: 320,
          background: "#23232a",
          borderRight: "1px solid #222",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* User Info */}
        <div style={{ padding: 24, borderBottom: "1px solid #222" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div
              style={{
                width: 44,
                height: 44,
                borderRadius: "50%",
                background: "#007bff",
                color: "#fff",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: 700,
                fontSize: 20,
              }}
            >
              {currentUser?.email?.charAt(0)?.toUpperCase() || "U"}
            </div>
            <div style={{ flex: 1 }}>
              <div
                style={{
                  fontWeight: 600,
                  fontSize: 15,
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {currentUser?.email}
              </div>
              <div style={{ fontSize: 12, color: "#7dd3fc" }}>
                {activeRoom ? "In room: " + activeRoom.name : "Not in a room"}
              </div>
            </div>
          </div>
        </div>
        {/* Friends List */}
        <div style={{ padding: 24, borderBottom: "1px solid #222", flex: 1 }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 10,
            }}
          >
            <div style={{ fontWeight: 600, fontSize: 14 }}>Friends</div>
            <button
              onClick={() => setShowAddFriend(true)}
              style={{
                background: "#007bff",
                color: "#fff",
                border: 0,
                borderRadius: 6,
                padding: "2px 10px",
                fontSize: 13,
                cursor: "pointer",
              }}
            >
              Add
            </button>
          </div>
          <div style={{ maxHeight: 120, overflowY: "auto" }}>
            {friends.length === 0 && (
              <div style={{ color: "#888", fontSize: 13 }}>No friends yet</div>
            )}
            {friends.map((f) => (
              <div
                key={f.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  marginBottom: 6,
                }}
              >
                <div
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: "50%",
                    background: f.online ? "#22c55e" : "#888",
                  }}
                ></div>
                <div style={{ fontSize: 13 }}>{f.name}</div>
                <button
                  style={{
                    marginLeft: "auto",
                    fontSize: 12,
                    color: "#007bff",
                    background: "none",
                    border: 0,
                    cursor: "pointer",
                  }}
                  onClick={() => setActiveRoom({ id: f.id, name: f.name })}
                >
                  Chat
                </button>
              </div>
            ))}
          </div>
        </div>
        {/* Rooms List */}
        <div style={{ padding: 24, borderBottom: "1px solid #222" }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 10 }}>
            Rooms
          </div>
          <div style={{ maxHeight: 80, overflowY: "auto" }}>
            {rooms.map((room) => (
              <div
                key={room.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  marginBottom: 6,
                }}
              >
                <div style={{ fontSize: 13 }}>{room.name}</div>
                <button
                  style={{
                    marginLeft: "auto",
                    fontSize: 12,
                    color: "#007bff",
                    background: "none",
                    border: 0,
                    cursor: "pointer",
                  }}
                  onClick={() => setActiveRoom(room)}
                >
                  Join
                </button>
              </div>
            ))}
          </div>
        </div>
        {/* Add Friend Modal */}
        {showAddFriend && (
          <div
            style={{
              position: "fixed",
              top: 0,
              left: 0,
              width: "100vw",
              height: "100vh",
              background: "rgba(0,0,0,0.4)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              zIndex: 100,
            }}
          >
            <div
              style={{
                background: "#23232a",
                padding: 32,
                borderRadius: 10,
                minWidth: 320,
              }}
            >
              <div style={{ fontWeight: 600, fontSize: 16, marginBottom: 16 }}>
                Add Friend
              </div>
              <input
                value={addFriendEmail}
                onChange={(e) => setAddFriendEmail(e.target.value)}
                placeholder="Enter email or username"
                style={{
                  width: "100%",
                  padding: 8,
                  borderRadius: 6,
                  border: "1px solid #333",
                  marginBottom: 16,
                  background: "#18181b",
                  color: "#fff",
                }}
              />
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={handleAddFriend}
                  style={{
                    flex: 1,
                    background: "#007bff",
                    color: "#fff",
                    border: 0,
                    borderRadius: 6,
                    padding: 8,
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                >
                  Add
                </button>
                <button
                  onClick={() => setShowAddFriend(false)}
                  style={{
                    flex: 1,
                    background: "#333",
                    color: "#fff",
                    border: 0,
                    borderRadius: 6,
                    padding: 8,
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
      {/* Main Area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        {/* Lobby/Welcome state */}
        {!activeRoom && (
          <div
            style={{
              flex: 1,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexDirection: "column",
              color: "#888",
            }}
          >
            <div style={{ fontSize: 22, fontWeight: 600, marginBottom: 10 }}>
              Welcome!
            </div>
            <div style={{ fontSize: 15 }}>
              Select a friend or room to start chatting.
            </div>
          </div>
        )}
        {/* Chat UI */}
        {activeRoom && (
          <>
            <div
              style={{
                flex: 1,
                overflowY: "auto",
                padding: 24,
                background: "#18181b",
              }}
            >
              {messages.length === 0 ? (
                <div
                  style={{ color: "#888", textAlign: "center", marginTop: 40 }}
                >
                  No messages yet. Start the conversation!
                </div>
              ) : (
                messages.map((message) => (
                  <div
                    key={message.id}
                    style={{
                      display: "flex",
                      justifyContent:
                        message.sender === "me" ? "flex-end" : "flex-start",
                      marginBottom: 18,
                    }}
                  >
                    <div
                      style={{
                        maxWidth: "70%",
                        padding: "12px 16px",
                        borderRadius: 18,
                        background:
                          message.sender === "me" ? "#007bff" : "#23232a",
                        color: "#fff",
                      }}
                    >
                      <div>{message.text}</div>
                      <div style={{ fontSize: 11, opacity: 0.7, marginTop: 5 }}>
                        {message.timestamp}
                        {message.sender === "me" && (
                          <span style={{ marginLeft: 5 }}>✓</span>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
              <div ref={messageEndRef} />
            </div>
            {/* Encryption Status */}
            {aesKey && (
              <div
                style={{
                  padding: "10px 24px",
                  background: "#23232a",
                  borderTop: "1px solid #222",
                  fontSize: 12,
                  color: "#22c55e",
                  display: "flex",
                  alignItems: "center",
                  gap: 5,
                }}
              >
                <span>🔒</span>
                <span>Messages are end-to-end encrypted</span>
              </div>
            )}
            {/* Input Area */}
            <div
              style={{
                padding: 24,
                background: "#23232a",
                borderTop: "1px solid #222",
              }}
            >
              {lastError && (
                <div
                  style={{
                    padding: 10,
                    background: "#4d1a1a",
                    borderRadius: 5,
                    marginBottom: 10,
                    fontSize: 12,
                    color: "#ff6b6b",
                  }}
                >
                  {lastError.message}
                </div>
              )}
              <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
                <textarea
                  value={messageInput}
                  onChange={(e) => setMessageInput(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder={
                    isConnected ? "Type a message..." : "Connecting..."
                  }
                  disabled={!isConnected}
                  style={{
                    flex: 1,
                    padding: 12,
                    border: "1px solid #444",
                    borderRadius: 20,
                    background: "#18181b",
                    color: "#fff",
                    resize: "none",
                    minHeight: 20,
                    maxHeight: 100,
                    outline: "none",
                  }}
                  rows={1}
                />
                <button
                  onClick={sendMessage}
                  disabled={!messageInput.trim() || !isConnected}
                  style={{
                    padding: "12px 20px",
                    background:
                      !messageInput.trim() || !isConnected ? "#444" : "#007bff",
                    color: "#fff",
                    border: "none",
                    borderRadius: 20,
                    cursor:
                      !messageInput.trim() || !isConnected
                        ? "not-allowed"
                        : "pointer",
                    fontWeight: "bold",
                  }}
                >
                  Send
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
