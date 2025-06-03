from flask_socketio import emit, join_room
from models.message import Message
from extensions import db

class SocketHandler:
    def __init__(self, socketio):
        self.socketio = socketio
        self.setup_handlers()
        
    def setup_handlers(self):
        @self.socketio.on('connect')
        def handle_connect():
            print("Client connected")
            
        @self.socketio.on('join_room')
        def handle_join_room(data):
            """Join user's personal room for direct messages"""
            user_id = data.get('user_id')
            if user_id:
                room = f"user_{user_id}"
                join_room(room)
                return {"status": "joined", "room": room}
                
        @self.socketio.on('relay_message')
        def handle_message(data):
            """
            Relay encrypted messages between users
            """
            try:
                # Store encrypted message
                message = Message(
                    sender_id=data['sender_id'],
                    recipient_id=data['recipient_id'],
                    encrypted_message=data['encrypted_message'],
                    message_type=data.get('message_type', 'text')
                )
                
                db.session.add(message)
                db.session.commit()
                
                # Relay to recipient
                recipient_room = f"user_{message.recipient_id}"
                emit('new_message', message.to_dict(), room=recipient_room)
                
                return {'status': 'sent', 'message_id': message.id}
                
            except Exception as e:
                return {'status': 'error', 'message': str(e)} 