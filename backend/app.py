from flask import Flask, jsonify
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from extensions import db
from models.message import Message
from routes.user_routes import user_bp

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Register blueprints
app.register_blueprint(user_bp, url_prefix='/api')

# Basic config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'  # For development
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

@app.route('/')
def index():
    return jsonify({"status": "ok", "message": "Server is running"})

@socketio.on('connect')
def handle_connect():
    print("Client connected")

@socketio.on('join_room')
def handle_join_room(data):
    """User joins their own room to receive messages"""
    user_id = data.get('user_id')
    if user_id:
        room = f"user_{user_id}"
        join_room(room)
        return {"status": "joined", "room": room}

@socketio.on('relay_message')
def handle_message(data):
    """
    Simply relay encrypted messages between users
    Frontend handles all encryption/decryption
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
