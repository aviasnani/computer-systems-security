from flask_socketio import emit, join_room, leave_room
from models.message import Message
from models.room import Room
from models.user import User
from extensions import db
from services.messaging.room_manager import RoomManager
from datetime import datetime, timezone
from sqlalchemy import desc

class SocketHandler:
    def __init__(self, socketio):
        self.socketio = socketio
        self.room_manager = RoomManager(socketio)
        self.setup_handlers()

    def setup_handlers(self):
        @self.socketio.on('connect')
        def handle_connect(auth_data=None):
            """Handle client connection with session-based authentication"""
            from flask import session, request

            print("Client connected")

            # Get user_id from session or auth_data
            user_id = session.get('user_id')
            if not user_id and auth_data and isinstance(auth_data, dict):
                user_id = auth_data.get('user_id')
                if user_id:
                    session['user_id'] = user_id  # Ensure stored in session

            if user_id:
                # Update user's online status and last seen
                user = User.query.get(user_id)
                if user:
                    user.last_seen = datetime.now(timezone.utc)
                    user.is_online = True
                    db.session.commit()

                    self.room_manager.presence_manager.set_user_online(user_id)

                    personal_room = f"user_{user_id}"
                    join_room(personal_room)
                    print(f"User {user_id} joined personal room: {personal_room}")

                    user_name = user.display_name or user.name or user.username or f"User {user_id}"
                    emit('connected', {
                        'status': 'connected',
                        'user_id': user_id,
                        'user_name': user_name,
                        'personal_room': personal_room
                    })

                    emit('user_online', {
                        'user_id': user_id,
                        'user_name': user_name,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }, broadcast=True, include_self=False)
                else:
                    emit('connected', {
                        'status': 'connected', 
                        'authenticated': False,
                        'error': 'User not found'
                    })
            else:
                emit('connected', {'status': 'connected', 'authenticated': False})

        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection and cleanup"""
            from flask import session
            print("Client disconnected")

            user_id = session.get('user_id')
            if user_id:
                self.room_manager.presence_manager.set_user_offline(user_id)
                print(f"User {user_id} marked as offline")

        @self.socketio.on('send_message')
        def handle_send_message(data):
            """Send a message to a chat room (supports both plain text and encrypted)"""
            try:
                sender_id = data.get('sender_id')
                room_id = data.get('room_id')
                content = data.get('content')
                message_type = data.get('message_type', 'text')
                encrypted_aes_key = data.get('encrypted_aes_key')
                iv = data.get('iv')
                signature = data.get('signature')
                is_encrypted = data.get('is_encrypted', False)
                original_content = data.get('original_content')

                if not sender_id or not room_id or not content:
                    emit('message_error', {
                        'status': 'error',
                        'message': 'sender_id, room_id, and content are required'
                    })
                    return

                if not self.room_manager.is_user_in_room(sender_id, room_id):
                    emit('message_error', {
                        'status': 'error',
                        'message': 'User is not in the specified room'
                    })
                    return

                message = Message(
                    sender_id=sender_id,
                    room_id=room_id,
                    content=content,
                    encrypted_aes_key=encrypted_aes_key,
                    iv=iv,
                    signature=signature,
                    is_encrypted=is_encrypted,
                    message_type=message_type,
                    original_content=original_content
                )
                db.session.add(message)
                db.session.commit()

                # Always get github_username from DB
                sender = User.query.get(sender_id)
                sender_github_username = sender.github_username if sender else None

                message_dict = message.to_dict()
                message_dict.update({
                    'github_username': sender_github_username,
                    'sender_name': sender.display_name or sender.name or sender.username if sender else 'Unknown User'
                })

                # Send confirmation to sender
                emit('message_sent', {
                    'status': 'sent',
                    'message_id': message.id,
                    'timestamp': message.timestamp.isoformat()
                })
                
                # Also send the message back to sender so they see it
                emit('new_message', message_dict)

                # Broadcast to other users in room
                broadcast_success = self.room_manager.broadcast_to_room(
                    room_id=room_id,
                    event='new_message',
                    data=message_dict,
                    exclude_user=sender_id
                )

                if not broadcast_success:
                    print(f"Warning: Failed to broadcast message {message.id} to room {room_id}")

                print(f"Message {message.id} sent to room {room_id} by user {sender_id} (encrypted: {is_encrypted})")

            except Exception as e:
                print(f"Error in send_message: {str(e)}")
                emit('message_error', {
                    'status': 'error',
                    'message': 'Failed to send message'
                })

        @self.socketio.on('get_all_users')
        def handle_get_all_users():
            """Get list of all registered users (online and offline)"""
            try:
                from flask import session
                
                current_user_id = session.get('user_id')
                print(f"get_all_users: current_user_id = {current_user_id}")
                
                if not current_user_id:
                    print("get_all_users: No current user in session")
                    emit('all_users_list', {'status': 'error', 'users': []})
                    return
                
                # Get all users except current user
                all_users_query = User.query.filter(User.id != current_user_id).all()
                online_user_ids = set(self.room_manager.presence_manager.get_online_users())
                
                all_users = []
                for user in all_users_query:
                    is_online = user.id in online_user_ids
                    all_users.append({
                        'id': user.id,
                        'username': user.username,
                        'name': user.name or user.username,
                        'email': user.email,
                        'display_name': user.display_name or user.name or user.username,
                        'github_username': user.github_username,
                        'last_seen': user.last_seen.isoformat() if user.last_seen else None,
                        'is_online': is_online
                    })
                    print(f"get_all_users: Added user {user.id} - {user.username} (online: {is_online})")
                
                print(f"get_all_users: Returning {len(all_users)} users")
                emit('all_users_list', {
                    'status': 'success',
                    'users': all_users
                })
                
            except Exception as e:
                print(f"Error in get_all_users: {str(e)}")
                import traceback
                traceback.print_exc()
                emit('all_users_list', {
                    'status': 'error',
                    'message': 'Failed to get all users',
                    'users': []
                })
        
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
                if not room:
                    if room_id == 'general':
                        room = Room(
                            id='general',
                            name='General Chat',
                            room_type='group',
                            created_by=user_id
                        )
                    elif '_' in room_id and len(room_id.split('_')) == 2:
                        user_ids = room_id.split('_')
                        try:
                            user1_id = int(user_ids[0])
                            user2_id = int(user_ids[1])
                            
                            user1 = User.query.get(user1_id)
                            user2 = User.query.get(user2_id)
                            
                            if user1 and user2:
                                room = Room(
                                    id=room_id,
                                    name=f"DM: {user1.display_name or user1.username} & {user2.display_name or user2.username}",
                                    room_type='direct',
                                    created_by=user_id
                                )
                            else:
                                emit('room_join_error', {
                                    'status': 'error',
                                    'message': f'One or both users in room {room_id} do not exist'
                                })
                                return
                        except ValueError:
                            emit('room_join_error', {
                                'status': 'error',
                                'message': f'Invalid room ID format: {room_id}'
                            })
                            return
                    else:
                        emit('room_join_error', {
                            'status': 'error',
                            'message': f'Room {room_id} does not exist'
                        })
                        return
                    
                    db.session.add(room)
                    db.session.commit()
                    print(f"Created new room: {room_id} ({room.room_type})")
                
                success = self.room_manager.add_user_to_room(user_id, room_id)
                
                if success:
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
