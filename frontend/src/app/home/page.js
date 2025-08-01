"use client"
import React, { useState, useRef, useEffect } from 'react';
import ProtectedRoute from '../components/ProtectedRoute';
import { useAuth } from '../../context/AuthContext';
import { useRouter } from 'next/navigation';


export default function ChatApp() {
  const [conversations, setConversations] = useState([
    {
      id: 1,
      name: "John Doe",
      lastMessage: "Hey, how are you?",
      timestamp: "2:30 PM",
      unread: 2,
      online: true,
      messages: [
        { id: 1, text: "Hi there!", sender: "other", timestamp: "2:25 PM" },
        { id: 2, text: "Hey, how are you?", sender: "other", timestamp: "2:30 PM" }
      ]
    },
    {
      id: 2,
      name: "Jane Smith",
      lastMessage: "See you tomorrow!",
      timestamp: "1:45 PM",
      unread: 0,
      online: false,
      messages: [
        { id: 1, text: "Thanks for the help!", sender: "me", timestamp: "1:40 PM" },
        { id: 2, text: "See you tomorrow!", sender: "other", timestamp: "1:45 PM" }
      ]
    },
    {
      id: 3,
      name: "Team Group",
      lastMessage: "Meeting at 3 PM",
      timestamp: "12:15 PM",
      unread: 5,
      online: true,
      isGroup: true,
      messages: [
        { id: 1, text: "Meeting at 3 PM", sender: "other", timestamp: "12:15 PM", senderName: "Mike" }
      ]
    }
  ]);

  const [activeChat, setActiveChat] = useState(1);
  const [messageInput, setMessageInput] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const messageEndRef = useRef(null);

  const currentConversation = conversations.find(conv => conv.id === activeChat);

  useEffect(() => {
    messageEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [currentConversation?.messages]);

  const sendMessage = () => {
    if (messageInput.trim()) {
      const newMessage = {
        id: Date.now(),
        text: messageInput,
        sender: "me",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      setConversations(prev => prev.map(conv => 
        conv.id === activeChat 
          ? { 
              ...conv, 
              messages: [...conv.messages, newMessage],
              lastMessage: messageInput,
              timestamp: newMessage.timestamp
            }
          : conv
      ));

      setMessageInput("");
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const { currentUser, logout } = useAuth();
  const router = useRouter();

  const handleLogout = async () => {
    try {
      await logout();
      router.push('/login');
    } catch (error) {
      console.error('Failed to log out:', error);
    }
  };

  const filteredConversations = conversations.filter(conv =>
    conv.name.toLowerCase().includes(searchQuery.toLowerCase())
  );



  return (
    <ProtectedRoute>
    <div style={{ display: 'flex', height: '100vh', fontFamily: 'Arial, sans-serif', backgroundColor: '#292828' }}>
      {/* Sidebar */}
      <div style={{ width: '300px', borderRight: '1px solid #ccc', display: 'flex', flexDirection: 'column' }}>
        {/* User Profile Section */}
        <div style={{ padding: '20px', borderBottom: '1px solid #eee' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '50%', backgroundColor: '#007bff', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white' }}>
              ME
            </div>
            <div>
              <div style={{ fontWeight: 'bold' }}>{currentUser?.displayName || "User"}</div>
              
            </div>
            
          </div>
        </div>
       
        
      
        {currentUser && (
            
              <button onClick={handleLogout} style={styles.button}>
                Logout
              </button>
            
          )}

        {/* Search */}
        <div style={{ padding: '10px' }}>
          <input
            type="text"
            placeholder="Search conversations..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ width: '100%', padding: '8px', border: '1px solid #ccc', borderRadius: '4px' }}
          />
        </div>

        

        {/* Conversations List */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filteredConversations.map(conv => (
            <div
              key={conv.id}
              onClick={() => setActiveChat(conv.id)}
              style={{
                padding: '15px',
                borderBottom: '1px solid #eee',
                cursor: 'pointer',
                backgroundColor: activeChat === conv.id ? '#f0f8ff' : 'transparent'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ position: 'relative' }}>
                  <div style={{ width: '40px', height: '40px', borderRadius: '50%', backgroundColor: '#28a745', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white' }}>
                    {conv.isGroup ? '👥' : conv.name.split(' ').map(n => n[0]).join('')}
                  </div>
                  {conv.online && (
                    <div style={{ position: 'absolute', bottom: '0', right: '0', width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#28a745', border: '2px solid white' }}></div>
                  )}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 'bold' }}>{conv.name}</span>
                    <span style={{ fontSize: '12px', color: '#666' }}>{conv.timestamp}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '14px', color: '#666', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {conv.lastMessage}
                    </span>
                    {conv.unread > 0 && (
                      <span style={{ backgroundColor: '#dc3545', color: 'white', borderRadius: '50%', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px' }}>
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
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {currentConversation ? (
          <>
            {/* Chat Header */}
            <div style={{ padding: '15px', borderBottom: '1px solid #ccc', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '50%', backgroundColor: '#28a745', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white' }}>
                {currentConversation.isGroup ? '👥' : currentConversation.name.split(' ').map(n => n[0]).join('')}
              </div>
              
            </div>

            {/* Messages Area */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '10px' }}>
              {currentConversation.messages.map(message => (
                <div
                  key={message.id}
                  style={{
                    display: 'flex',
                    justifyContent: message.sender === 'me' ? 'flex-end' : 'flex-start',
                    marginBottom: '10px'
                  }}
                >
                  <div
                    style={{
                      maxWidth: '70%',
                      padding: '10px',
                      borderRadius: '10px',
                      backgroundColor: message.sender === 'me' ? '#007bff' : '#f1f1f1',
                      color: message.sender === 'me' ? 'white' : 'black'
                    }}
                  >
                    {message.senderName && (
                      <div style={{ fontSize: '12px', fontWeight: 'bold', marginBottom: '5px' }}>
                        {message.senderName}
                      </div>
                    )}
                    <div>{message.text}</div>
                    <div style={{ fontSize: '11px', opacity: 0.7, marginTop: '5px' }}>
                      {message.timestamp}
                      {message.sender === 'me' && <span style={{ marginLeft: '5px' }}>✓✓</span>}
                    </div>
                  </div>
                </div>
              ))}
              <div ref={messageEndRef} />
            </div>

            {/* Message Input Area */}
            <div style={{ padding: '15px', borderTop: '1px solid #ccc' }}>
              
              <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-end' }}>
                
                <textarea
                  value={messageInput}
                  onChange={(e) => setMessageInput(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="Type a message..."
                  style={{
                    flex: 1,
                    padding: '10px',
                    border: '1px solid #ccc',
                    borderRadius: '4px',
                    resize: 'none',
                    minHeight: '40px',
                    maxHeight: '100px'
                  }}
                  rows={1}
                />
                
                <button onClick={sendMessage} disabled={!messageInput.trim()}>
                  Send
                </button>
              </div>
            </div>
          </>
        ) : (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#666' }}>
            Select a conversation to start chatting
          </div>
        )}
      </div>

      {/* Settings Panel */}
      {showSettings && (
        <div style={{ position: 'absolute', top: '80px', left: '20px', width: '250px', backgroundColor: 'white', border: '1px solid #ccc', borderRadius: '4px', padding: '15px', boxShadow: '0 2px 10px rgba(0,0,0,0.1)' }}>
          <h3>Settings</h3>
          <div style={{ marginBottom: '10px' }}>
            <label>
              <input type="checkbox" /> Notifications
            </label>
          </div>
          <div style={{ marginBottom: '10px' }}>
            <label>
              <input type="checkbox" /> Sound
            </label>
          </div>
          <div style={{ marginBottom: '10px' }}>
            <label>Theme:</label>
            <select style={{ marginLeft: '5px' }}>
              <option>Light</option>
              <option>Dark</option>
            </select>
          </div>
          <button onClick={() => setShowSettings(false)}>Close</button>
        </div>
      )}
    </div>
    </ProtectedRoute>
  );
}

const styles = {
  container: {
    display: 'flex',
    height: '100vh',
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#f5f5f5',
  },
  card: {
    padding: 30,
    backgroundColor: '#fff',
    borderRadius: 10,
    boxShadow: '0 4px 20px rgba(0,0,0,0.1)',
    textAlign: 'center',
  },
  button: {
    padding: '10px 20px',
    backgroundColor: '#dc3545',
    color: '#fff',
    border: 'none',
    borderRadius: 5,
    cursor: 'pointer',
    marginTop: 15,
  },
  image: {
    width: 80,
    borderRadius: '50%',
    margin: '10px 0',
  }
};