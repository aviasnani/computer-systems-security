from flask_socketio import emit, join_room, leave_room
from models.message import Message
from models.room import Room
from extensions import db
from services.messaging.room_manager import RoomManager

class SocketHandler:
    def __init__(self, socketio):
        self.socketio = socketio
        self.room_manager = RoomManager(socketio)
        self.setup_handlers()
        
    def setup_handlers(self):
        @self.socketio.on('connect')
        def handle_connect(auth_data=None):
            """Handle client connection with authentication"""
            print("Client connected")
            
            # Extract user_id from auth data if provided
            user_id = None
            if auth_data and isinstance(auth_data, dict):
                user_id = auth_data.get('user_id')
            
            if user_id:
                # Join user's personal room for direct communication
                personal_room = f"user_{user_id}"
                join_room(personal_room)
                print(f"User {user_id} joined personal room: {personal_room}")
                
                emit('connected', {
                    'status': 'connected',
                    'user_id': user_id,
                    'personal_room': personal_room
                })
            else:
                emit('connected', {'status': 'connected'})
            
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection and cleanup"""
            print("Client disconnected")
            
            
        @self.socketio.on('join_room')
        def handle_join_room(data):
            """Join a chat room for group conversations"""
            try:
                user_id = data.get('user_id')
                room_id = data.get('room_id')
                
                if not user_id or not room_id:
                    emit('room_join_error', {
                        'status': 'error',
                        'message': 'user_id and room_id are required'
                    })
                    return
                
                # Check if room exists, create if it doesn't 
                room = Room.query.filter_by(id=room_id).first()
                if not room and room_id == 'general':
                    # Auto-create general room
                    room = Room(
                        id='general',
                        name='General Chat',
                        created_by=user_id
                    )
                    db.session.add(room)
                    db.session.commit()
                elif not room:
                    emit('room_join_error', {
                        'status': 'error',
                        'message': f'Room {room_id} does not exist'
                    })
                    return
                
                # Add user to room in room manager
                success = self.room_manager.add_user_to_room(user_id, room_id)
                
                if success:
                    # Join the socket.io room
                    join_room(room_id)
                    
                    emit('room_joined', {
                        'status': 'joined',
                        'room_id': room_id,
                        'room_name': room.name,
                        'user_count': len(self.room_manager.get_room_users(room_id))
                    })
                    
                    print(f"User {user_id} joined room: {room_id}")
                else:
                    emit('room_join_error', {
                        'status': 'error',
                        'message': 'Failed to join room'
                    })
                    
            except Exception as e:
                print(f"Error in join_room: {str(e)}")
                emit('room_join_error', {
                    'status': 'error',
                    'message': 'Internal server error'
                })
        
        @self.socketio.on('leave_room')
        def handle_leave_room(data):
            """Leave a chat room"""
            try:
                user_id = data.get('user_id')
                room_id = data.get('room_id')
                
                if not user_id or not room_id:
                    emit('room_leave_error', {
                        'status': 'error',
                        'message': 'user_id and room_id are required'
                    })
                    return
                
                # Remove user from room in room manager
                success = self.room_manager.remove_user_from_room(user_id, room_id)
                
                if success:
                    # Leave the socket.io room
                    leave_room(room_id)
                    
                    emit('room_left', {
                        'status': 'left',
                        'room_id': room_id
                    })
                    
                    print(f"User {user_id} left room: {room_id}")
                else:
                    emit('room_leave_error', {
                        'status': 'error',
                        'message': 'Failed to leave room'
                    })
                    
            except Exception as e:
                print(f"Error in leave_room: {str(e)}")
                emit('room_leave_error', {
                    'status': 'error',
                    'message': 'Internal server error'
                })
                
        @self.socketio.on('send_message')
        def handle_send_message(data):
            """Send a message to a chat room"""
            try:
                sender_id = data.get('sender_id')
                room_id = data.get('room_id')
                content = data.get('content')
                message_type = data.get('message_type', 'text')
                
                if not sender_id or not room_id or not content:
                    emit('message_error', {
                        'status': 'error',
                        'message': 'sender_id, room_id, and content are required'
                    })
                    return
                
                # Verify user is in the room
                if not self.room_manager.is_user_in_room(sender_id, room_id):
                    emit('message_error', {
                        'status': 'error',
                        'message': 'User is not in the specified room'
                    })
                    return
                
                # Create and store the message
                message = Message(
                    sender_id=sender_id,
                    room_id=room_id,
                    content=content,
                    message_type=message_type
                )
                
                db.session.add(message)
                db.session.commit()
                
                # Send confirmation to sender
                emit('message_sent', {
                    'status': 'sent',
                    'message_id': message.id,
                    'timestamp': message.timestamp.isoformat()
                })
                
                # Broadcast message to all users in the room (excluding sender)
                broadcast_success = self.room_manager.broadcast_message_to_room(
                    room_id=room_id,
                    message=message,
                    exclude_sender=True
                )
                
                if not broadcast_success:
                    print(f"Warning: Failed to broadcast message {message.id} to room {room_id}")
                
                print(f"Message {message.id} sent to room {room_id} by user {sender_id}")
                
            except Exception as e:
                print(f"Error in send_message: {str(e)}")
                emit('message_error', {
                    'status': 'error',
                    'message': 'Failed to send message'
                })
                
