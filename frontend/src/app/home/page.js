"use client"
import React, { useState, useRef, useEffect } from 'react';
import ProtectedRoute from '../components/ProtectedRoute';
import { useAuth } from '../../context/AuthContext';
import { useRouter } from 'next/navigation';
import { useChat } from '../../hooks/useChat';
import { useKeyManagement } from '../../hooks/useKeyManagement';
import { useFriends } from '../../hooks/useFriends';

export default function ChatApp() {
  const [activeSection, setActiveSection] = useState('friends'); // 'friends' or 'rooms'
  const [selectedChat, setSelectedChat] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [showAddFriend, setShowAddFriend] = useState(false);
  const [addFriendEmail, setAddFriendEmail] = useState("");
  const [isAddingFriend, setIsAddingFriend] = useState(false);
  const messageEndRef = useRef(null);

  const { currentUser, logout } = useAuth();
  const router = useRouter();

  // Key management for encryption
  const { rsaKeys, isGenerating } = useKeyManagement(currentUser?.uid);

  // Friends management
  const {
    friends,
    pendingRequests,
    isLoading: friendsLoading,
    sendFriendRequest,
    acceptFriendRequest,
    rejectFriendRequest,
    removeFriend,
    searchUsers
  } = useFriends(currentUser?.uid);

  // Chat functionality with encryption
  const {
    messages,
    isConnected,
    sendMessage,
    connectionError,
    lastError,
    recipientKeys,
    isLoadingKeys,
    refreshKeys
  } = useChat(selectedChat?.id || 'general', currentUser?.uid, null, rsaKeys); // Remove token dependency for now

  // Sample rooms data
  const [rooms] = useState([
    { id: 'general', name: 'General Chat', description: 'General discussion room' },
    { id: 'tech', name: 'Tech Talk', description: 'Technology discussions' },
    { id: 'random', name: 'Random', description: 'Random conversations' }
  ]);

  // Connection status
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const [backendAvailable, setBackendAvailable] = useState(true);

  useEffect(() => {
    // Check backend availability
    const checkBackend = async () => {
      try {
        const response = await fetch('http://localhost:5001/', { 
          method: 'GET',
          timeout: 3000 
        });
        setBackendAvailable(response.ok);
        setConnectionStatus(response.ok ? 'connected' : 'error');
      } catch (error) {
        console.warn('Backend not available:', error);
        setBackendAvailable(false);
        setConnectionStatus('error');
      }
    };

    checkBackend();
    const interval = setInterval(checkBackend, 10000); // Check every 10 seconds

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    messageEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSendMessage = async (messageText) => {
    if (messageText.trim() && selectedChat) {
      const result = await sendMessage(messageText.trim());
      if (!result.success) {
        console.error('Failed to send message:', result.error);
      }
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      const messageInput = e.target.value;
      e.target.value = '';
      handleSendMessage(messageInput);
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
      router.push('/login');
    } catch (error) {
      console.error('Failed to log out:', error);
    }
  };

  const handleAddFriend = async () => {
    if (!addFriendEmail.trim()) return;
    
    setIsAddingFriend(true);
    try {
      const success = await sendFriendRequest(addFriendEmail);
      if (success) {
        setAddFriendEmail("");
        setShowAddFriend(false);
        alert('Friend request sent successfully!');
      } else {
        alert('Failed to send friend request');
      }
    } catch (error) {
      alert('Error sending friend request');
    } finally {
      setIsAddingFriend(false);
    }
  };

  const handleAcceptRequest = async (requestId) => {
    const success = await acceptFriendRequest(requestId);
    if (success) {
      alert('Friend request accepted!');
    } else {
      alert('Failed to accept friend request');
    }
  };

  const handleRejectRequest = async (requestId) => {
    const success = await rejectFriendRequest(requestId);
    if (success) {
      alert('Friend request rejected');
    } else {
      alert('Failed to reject friend request');
    }
  };

  const handleJoinRoom = (room) => {
    setSelectedChat(room);
    setActiveSection('chat');
  };

  const handleSelectFriend = (friend) => {
    setSelectedChat(friend);
    setActiveSection('chat');
  };

  const filteredFriends = friends.filter(friend =>
    friend.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    friend.email?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredRooms = rooms.filter(room =>
    room.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <ProtectedRoute>
      <div style={styles.container}>
        {/* Left Sidebar */}
        <div style={styles.sidebar}>
          {/* User Profile Section */}
          <div style={styles.userProfile}>
            <div style={styles.avatar}>
              {currentUser?.displayName?.charAt(0) || currentUser?.email?.charAt(0) || 'U'}
            </div>
            <div style={styles.userInfo}>
              <div style={styles.userName}>{currentUser?.displayName || 'User'}</div>
              <div style={styles.userEmail}>{currentUser?.email}</div>
              <div style={styles.userStatus}>
                {backendAvailable ? (
                  isConnected ? '🟢 Online' : '🟡 Connecting...'
                ) : (
                  '🔴 Backend Offline'
                )}
                {isGenerating && ' (Generating Keys...)'}
              </div>
            </div>
            <button onClick={handleLogout} style={styles.logoutButton}>
              Logout
            </button>
          </div>

          {/* Encryption Status */}
          <div style={styles.encryptionStatus}>
            <div style={styles.encryptionText}>
              🔐 Encryption: {rsaKeys ? 'Enabled' : 'Setting up...'}
            </div>
            {backendAvailable && recipientKeys && Object.keys(recipientKeys).length > 0 && (
              <div style={styles.recipientCount}>
                📡 {Object.keys(recipientKeys).length} recipient(s)
              </div>
            )}
            {!backendAvailable && (
              <div style={styles.backendWarning}>
                ⚠️ Backend server is offline
              </div>
            )}
          </div>

          {/* Navigation Tabs */}
          <div style={styles.navTabs}>
            <button
              onClick={() => setActiveSection('friends')}
              style={{
                ...styles.navTab,
                ...(activeSection === 'friends' && styles.activeNavTab)
              }}
            >
              Friends
            </button>
            <button
              onClick={() => setActiveSection('rooms')}
              style={{
                ...styles.navTab,
                ...(activeSection === 'rooms' && styles.activeNavTab)
              }}
            >
              Rooms
            </button>
          </div>

          {/* Search */}
          <div style={styles.searchContainer}>
            <input
              type="text"
              placeholder="Search..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={styles.searchInput}
            />
          </div>

          {/* Content Area */}
          <div style={styles.contentArea}>
            {activeSection === 'friends' && (
              <div>
                <div style={styles.sectionHeader}>
                  <h3 style={styles.sectionTitle}>Friends</h3>
                  <button
                    onClick={() => setShowAddFriend(!showAddFriend)}
                    style={styles.addButton}
                  >
                    Add
                  </button>
                </div>

                {/* Add Friend Form */}
                {showAddFriend && (
                  <div style={styles.addFriendForm}>
                    <input
                      type="email"
                      placeholder="Enter email address"
                      value={addFriendEmail}
                      onChange={(e) => setAddFriendEmail(e.target.value)}
                      style={styles.addFriendInput}
                    />
                    <button
                      onClick={handleAddFriend}
                      disabled={isAddingFriend}
                      style={styles.addFriendButton}
                    >
                      {isAddingFriend ? 'Sending...' : 'Send Request'}
                    </button>
                  </div>
                )}

                {/* Friends List */}
                {friendsLoading ? (
                  <div style={styles.loadingText}>Loading friends...</div>
                ) : friends.length === 0 ? (
                  <div style={styles.emptyText}>No friends yet</div>
                ) : (
                  <div style={styles.friendsList}>
                    {filteredFriends.map(friend => (
                      <div
                        key={friend.id}
                        onClick={() => handleSelectFriend(friend)}
                        style={styles.friendItem}
                      >
                        <div style={styles.friendAvatar}>
                          {friend.name?.charAt(0) || friend.email?.charAt(0)}
                        </div>
                        <div style={styles.friendInfo}>
                          <div style={styles.friendName}>{friend.name || 'Unknown'}</div>
                          <div style={styles.friendEmail}>{friend.email}</div>
                        </div>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            removeFriend(friend.id);
                          }}
                          style={styles.removeButton}
                        >
                          ×
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {/* Pending Requests */}
                {pendingRequests.length > 0 && (
                  <div style={styles.pendingSection}>
                    <h4 style={styles.pendingTitle}>Pending Requests ({pendingRequests.length})</h4>
                    {pendingRequests.map(request => (
                      <div key={request.id} style={styles.requestItem}>
                        <div style={styles.requestInfo}>
                          <div style={styles.requestName}>{request.sender_name}</div>
                          <div style={styles.requestEmail}>{request.sender_email}</div>
                        </div>
                        <div style={styles.requestActions}>
                          <button
                            onClick={() => handleAcceptRequest(request.id)}
                            style={styles.acceptButton}
                          >
                            ✓
                          </button>
                          <button
                            onClick={() => handleRejectRequest(request.id)}
                            style={styles.rejectButton}
                          >
                            ✕
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeSection === 'rooms' && (
              <div>
                <div style={styles.sectionHeader}>
                  <h3 style={styles.sectionTitle}>Rooms</h3>
                  {!backendAvailable && (
                    <div style={styles.offlineNotice}>Offline Mode</div>
                  )}
                </div>
                <div style={styles.roomsList}>
                  {filteredRooms.map(room => (
                    <div
                      key={room.id}
                      onClick={() => handleJoinRoom(room)}
                      style={styles.roomItem}
                    >
                      <div style={styles.roomIcon}>#</div>
                      <div style={styles.roomInfo}>
                        <div style={styles.roomName}>{room.name}</div>
                        <div style={styles.roomDescription}>{room.description}</div>
                      </div>
                      <button 
                        style={styles.joinButton}
                        disabled={!backendAvailable}
                      >
                        Join
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Main Chat Area */}
        <div style={styles.chatArea}>
          {selectedChat ? (
            <>
              {/* Chat Header */}
              <div style={styles.chatHeader}>
                <div style={styles.chatInfo}>
                  <div style={styles.chatAvatar}>
                    {selectedChat.name?.charAt(0) || '#'}
                  </div>
                  <div>
                    <div style={styles.chatName}>{selectedChat.name}</div>
                    <div style={styles.chatStatus}>
                      {backendAvailable ? (
                        isConnected ? '🟢 Connected' : '🟡 Connecting...'
                      ) : (
                        '🔴 Backend Offline'
                      )}
                    </div>
                  </div>
                </div>
                <button
                  onClick={refreshKeys}
                  style={styles.refreshButton}
                  disabled={isLoadingKeys}
                >
                  🔄 Refresh Keys
                </button>
              </div>

              {/* Messages Area */}
              <div style={styles.messagesArea}>
                {messages.map(message => (
                  <div
                    key={message.id}
                    style={{
                      ...styles.messageContainer,
                      justifyContent: message.sender === 'me' ? 'flex-end' : 'flex-start'
                    }}
                  >
                    <div
                      style={{
                        ...styles.message,
                        backgroundColor: message.sender === 'me' ? '#007bff' : '#2d2d2d',
                        color: message.sender === 'me' ? 'white' : '#ffffff'
                      }}
                    >
                      <div style={styles.messageText}>{message.text}</div>
                      <div style={styles.messageMeta}>
                        {message.timestamp}
                        {message.isEncrypted && <span style={styles.encryptedIcon}>🔐</span>}
                        {message.sender === 'me' && <span style={styles.sentIcon}>✓✓</span>}
                      </div>
                    </div>
                  </div>
                ))}
                <div ref={messageEndRef} />
              </div>

              {/* Error Display */}
              {lastError && (
                <div style={styles.errorMessage}>
                  Error: {lastError.message}
                </div>
              )}

              {/* Message Input */}
              <div style={styles.messageInput}>
                <textarea
                  placeholder={backendAvailable ? "Type a message..." : "Backend offline - cannot send messages"}
                  onKeyPress={handleKeyPress}
                  style={{
                    ...styles.input,
                    opacity: backendAvailable ? 1 : 0.5,
                    cursor: backendAvailable ? 'text' : 'not-allowed'
                  }}
                  rows={1}
                  disabled={!backendAvailable}
                />
              </div>
            </>
          ) : (
            <div style={styles.welcomeArea}>
              <h1 style={styles.welcomeTitle}>Welcome!</h1>
              <p style={styles.welcomeText}>
                Select a friend or room to start chatting.
              </p>
            </div>
          )}
        </div>
      </div>
    </ProtectedRoute>
  );
}

const styles = {
  container: {
    display: 'flex',
    height: '100vh',
    backgroundColor: '#1a1a1a',
    fontFamily: 'Arial, sans-serif',
  },
  sidebar: {
    width: '300px',
    backgroundColor: '#2d2d2d',
    borderRight: '1px solid #404040',
    display: 'flex',
    flexDirection: 'column',
  },
  userProfile: {
    padding: '20px',
    borderBottom: '1px solid #404040',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  avatar: {
    width: '40px',
    height: '40px',
    borderRadius: '50%',
    backgroundColor: '#007bff',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'white',
    fontWeight: 'bold',
    fontSize: '16px',
  },
  userInfo: {
    flex: 1,
  },
  userName: {
    color: '#ffffff',
    fontWeight: 'bold',
    fontSize: '14px',
  },
  userEmail: {
    color: '#b0b0b0',
    fontSize: '12px',
  },
  userStatus: {
    color: '#28a745',
    fontSize: '11px',
  },
  logoutButton: {
    padding: '6px 12px',
    backgroundColor: '#dc3545',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    fontSize: '12px',
    cursor: 'pointer',
  },
  encryptionStatus: {
    padding: '10px 20px',
    backgroundColor: '#1a1a1a',
    borderBottom: '1px solid #404040',
  },
  encryptionText: {
    color: '#b0b0b0',
    fontSize: '12px',
  },
  recipientCount: {
    color: '#28a745',
    fontSize: '11px',
    marginTop: '4px',
  },
  backendWarning: {
    color: '#ffc107',
    fontSize: '11px',
    marginTop: '4px',
  },
  offlineNotice: {
    color: '#ffc107',
    fontSize: '12px',
    padding: '4px 8px',
    backgroundColor: '#1a1a1a',
    borderRadius: '4px',
    border: '1px solid #ffc107',
  },
  navTabs: {
    display: 'flex',
    borderBottom: '1px solid #404040',
  },
  navTab: {
    flex: 1,
    padding: '12px',
    backgroundColor: 'transparent',
    border: 'none',
    color: '#b0b0b0',
    cursor: 'pointer',
    fontSize: '14px',
  },
  activeNavTab: {
    backgroundColor: '#007bff',
    color: 'white',
  },
  searchContainer: {
    padding: '15px 20px',
  },
  searchInput: {
    width: '100%',
    padding: '8px 12px',
    border: '1px solid #404040',
    borderRadius: '6px',
    backgroundColor: '#1a1a1a',
    color: '#ffffff',
    fontSize: '14px',
  },
  contentArea: {
    flex: 1,
    overflowY: 'auto',
    padding: '20px',
  },
  sectionHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '15px',
  },
  sectionTitle: {
    color: '#ffffff',
    fontSize: '16px',
    margin: 0,
  },
  addButton: {
    padding: '6px 12px',
    backgroundColor: '#007bff',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    fontSize: '12px',
    cursor: 'pointer',
  },
  addFriendForm: {
    marginBottom: '15px',
    padding: '15px',
    backgroundColor: '#1a1a1a',
    borderRadius: '6px',
  },
  addFriendInput: {
    width: '100%',
    padding: '8px',
    border: '1px solid #404040',
    borderRadius: '4px',
    backgroundColor: '#2d2d2d',
    color: '#ffffff',
    marginBottom: '8px',
  },
  addFriendButton: {
    width: '100%',
    padding: '8px',
    backgroundColor: '#28a745',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
  },
  loadingText: {
    color: '#b0b0b0',
    textAlign: 'center',
    padding: '20px',
  },
  emptyText: {
    color: '#b0b0b0',
    textAlign: 'center',
    padding: '20px',
  },
  friendsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
  },
  friendItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '10px',
    backgroundColor: '#1a1a1a',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.2s',
  },
  friendAvatar: {
    width: '32px',
    height: '32px',
    borderRadius: '50%',
    backgroundColor: '#28a745',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'white',
    fontSize: '14px',
  },
  friendInfo: {
    flex: 1,
  },
  friendName: {
    color: '#ffffff',
    fontSize: '14px',
    fontWeight: '500',
  },
  friendEmail: {
    color: '#b0b0b0',
    fontSize: '12px',
  },
  removeButton: {
    padding: '4px 8px',
    backgroundColor: '#dc3545',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '12px',
  },
  pendingSection: {
    marginTop: '20px',
  },
  pendingTitle: {
    color: '#ffffff',
    fontSize: '14px',
    marginBottom: '10px',
  },
  requestItem: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '10px',
    backgroundColor: '#1a1a1a',
    borderRadius: '6px',
    marginBottom: '8px',
  },
  requestInfo: {
    flex: 1,
  },
  requestName: {
    color: '#ffffff',
    fontSize: '14px',
  },
  requestEmail: {
    color: '#b0b0b0',
    fontSize: '12px',
  },
  requestActions: {
    display: 'flex',
    gap: '5px',
  },
  acceptButton: {
    padding: '4px 8px',
    backgroundColor: '#28a745',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
  },
  rejectButton: {
    padding: '4px 8px',
    backgroundColor: '#dc3545',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
  },
  roomsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
  },
  roomItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '10px',
    backgroundColor: '#1a1a1a',
    borderRadius: '6px',
    cursor: 'pointer',
  },
  roomIcon: {
    width: '32px',
    height: '32px',
    borderRadius: '50%',
    backgroundColor: '#ffc107',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: '#1a1a1a',
    fontSize: '16px',
    fontWeight: 'bold',
  },
  roomInfo: {
    flex: 1,
  },
  roomName: {
    color: '#ffffff',
    fontSize: '14px',
    fontWeight: '500',
  },
  roomDescription: {
    color: '#b0b0b0',
    fontSize: '12px',
  },
  joinButton: {
    padding: '6px 12px',
    backgroundColor: '#007bff',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    fontSize: '12px',
    cursor: 'pointer',
  },
  chatArea: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    backgroundColor: '#1a1a1a',
  },
  chatHeader: {
    padding: '15px 20px',
    borderBottom: '1px solid #404040',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  chatInfo: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  chatAvatar: {
    width: '40px',
    height: '40px',
    borderRadius: '50%',
    backgroundColor: '#28a745',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'white',
    fontSize: '16px',
  },
  chatName: {
    color: '#ffffff',
    fontSize: '16px',
    fontWeight: 'bold',
  },
  chatStatus: {
    color: '#b0b0b0',
    fontSize: '12px',
  },
  refreshButton: {
    padding: '8px 12px',
    backgroundColor: '#6c757d',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    fontSize: '12px',
    cursor: 'pointer',
  },
  messagesArea: {
    flex: 1,
    overflowY: 'auto',
    padding: '20px',
  },
  messageContainer: {
    display: 'flex',
    marginBottom: '10px',
  },
  message: {
    maxWidth: '70%',
    padding: '12px 16px',
    borderRadius: '12px',
    fontSize: '14px',
  },
  messageText: {
    marginBottom: '4px',
  },
  messageMeta: {
    fontSize: '11px',
    opacity: 0.7,
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
  },
  encryptedIcon: {
    fontSize: '12px',
  },
  sentIcon: {
    fontSize: '12px',
  },
  errorMessage: {
    padding: '10px 20px',
    backgroundColor: '#dc3545',
    color: 'white',
    fontSize: '14px',
  },
  messageInput: {
    padding: '20px',
    borderTop: '1px solid #404040',
  },
  input: {
    width: '100%',
    padding: '12px 16px',
    border: '1px solid #404040',
    borderRadius: '8px',
    backgroundColor: '#2d2d2d',
    color: '#ffffff',
    fontSize: '14px',
    resize: 'none',
    outline: 'none',
  },
  welcomeArea: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    color: '#ffffff',
  },
  welcomeTitle: {
    fontSize: '32px',
    fontWeight: 'bold',
    marginBottom: '10px',
  },
  welcomeText: {
    fontSize: '16px',
    color: '#b0b0b0',
  },
};