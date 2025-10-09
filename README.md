# 🔐 End-to-End Encrypted Chat Application

A secure, real-time chat application with end-to-end encryption, friends management, and modern UI.

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- Python 3.8+
- Firebase project (for authentication)

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd computer-systems-security
```

2. **Backend Setup**
```bash
cd backend
pip install -r requirements.txt
python init_db.py
python run.py
```
Backend runs on: `http://localhost:5001`

3. **Frontend Setup**
```bash
cd frontend
npm install
npm run dev
```
Frontend runs on: `http://localhost:3000`

## 🔗 URL Structure

### Frontend URLs (Next.js)
| URL | Description | Access |
|-----|-------------|---------|
| `/` | Landing page (redirects to login/home) | Public |
| `/login` | User login page | Public |
| `/register` | User registration page | Public |
| `/home` | Main chat application | Protected |

### Backend API URLs (Flask)
| URL | Method | Description |
|-----|--------|-------------|
| `http://localhost:5001/` | GET | Health check |
| `http://localhost:5001/api/auth/firebase` | POST | Firebase authentication |
| `http://localhost:5001/api/auth/signup` | POST | User registration |
| `http://localhost:5001/api/auth/login` | POST | User login |
| `http://localhost:5001/api/auth/check` | GET | Check authentication |
| `http://localhost:5001/api/public-key` | POST | Store public key |
| `http://localhost:5001/api/users/{id}/public-key` | GET | Get user's public key |
| `http://localhost:5001/api/users/online` | GET | Get online users |
| `http://localhost:5001/api/users/batch-keys` | POST | Get multiple users' keys |
| `http://localhost:5001/api/friends` | GET | Get friends list |
| `http://localhost:5001/api/friends/requests` | GET | Get pending requests |
| `http://localhost:5001/api/friends/request` | POST | Send friend request |
| `http://localhost:5001/api/friends/accept/{id}` | POST | Accept friend request |
| `http://localhost:5001/api/friends/reject/{id}` | POST | Reject friend request |
| `http://localhost:5001/api/friends/remove/{id}` | DELETE | Remove friend |
| `http://localhost:5001/api/users/search` | GET | Search users |

## 🔐 Security Features

### End-to-End Encryption
- **RSA-2048** for key exchange
- **AES-256-GCM** for message encryption
- **Hybrid encryption** for optimal performance
- **Client-side key generation** and management

### Authentication
- **Firebase Authentication** integration
- **JWT token** validation
- **Session management** with secure cookies

## 🏗️ Architecture

### Frontend (Next.js 15 + React 19)
```
frontend/
├── src/
│   ├── app/                 # Next.js App Router
│   │   ├── components/      # Reusable components
│   │   ├── home/           # Main chat interface
│   │   ├── login/          # Login page
│   │   └── register/       # Registration page
│   ├── context/            # React context providers
│   ├── hooks/              # Custom React hooks
│   └── services/           # API and utility services
```

### Backend (Flask + Socket.IO)
```
backend/
├── routes/                 # API endpoints
├── models/                 # Database models
├── services/               # Business logic
│   ├── auth/              # Authentication services
│   ├── messaging/         # WebSocket and chat logic
│   └── security/          # Encryption and key management
└── config/                # Configuration files
```

## 🎯 Features

### ✅ Implemented
- [x] User registration and authentication
- [x] End-to-end encrypted messaging
- [x] Friends management (add, accept, reject, remove)
- [x] Real-time chat with WebSocket
- [x] Room-based group chats
- [x] Modern dark theme UI
- [x] Responsive design
- [x] Key management and exchange
- [x] Message encryption/decryption
- [x] Connection status indicators

### 🔄 In Progress
- [ ] File sharing with encryption
- [ ] Message history persistence
- [ ] Online/offline status
- [ ] Message delivery receipts
- [ ] Group chat encryption

## 🛠️ Development

### Running in Development
```bash
# Terminal 1 - Backend
cd backend
python run.py

# Terminal 2 - Frontend  
cd frontend
npm run dev
```

### Database
- **SQLite** for development
- Automatic schema creation with `init_db.py`
- Models: User, Message, FriendRequest, Room

### Environment Variables
Create `.env.local` in frontend directory:
```env
NEXT_PUBLIC_FIREBASE_API_KEY=your_firebase_api_key
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
NEXT_PUBLIC_FIREBASE_PROJECT_ID=your_project_id
NEXT_PUBLIC_WEBSOCKET_URL=http://localhost:5001
```

## 🔧 Troubleshooting

### Common Issues

1. **"Backend Offline" status**
   - Ensure backend is running on port 5001
   - Check firewall settings
   - Verify CORS configuration

2. **Authentication errors**
   - Check Firebase configuration
   - Verify environment variables
   - Clear browser cache

3. **WebSocket connection issues**
   - Check if Socket.IO server is running
   - Verify port 5001 is accessible
   - Check browser console for errors

4. **Encryption not working**
   - Ensure Web Crypto API is available
   - Check browser compatibility
   - Verify key generation process

### Debug Mode
```bash
# Backend with debug
python run.py  # Debug mode enabled

# Frontend with debug
npm run dev    # Development mode with hot reload
```

## 📱 Usage

1. **Register/Login**: Visit `/register` or `/login`
2. **Add Friends**: Use the "Add" button in Friends tab
3. **Join Rooms**: Click "Join" on any room
4. **Start Chatting**: Select a friend or room to begin
5. **Encryption**: Keys are automatically generated and exchanged

## 🔒 Security Notes

- All messages are encrypted client-side before transmission
- Private keys never leave the client
- Server cannot decrypt message content
- Keys are regenerated on each session
- HTTPS recommended for production

## 📄 License

This project is for educational purposes. Use at your own risk.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

**Note**: This is a demonstration project for computer systems security. For production use, additional security measures should be implemented. 