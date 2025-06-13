from flask import Flask, jsonify
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from extensions import db
from models.message import Message
from routes.user_routes import user_bp


'''from flask import Flask, render_template, request, redirect, url_for, flashAdd commentMore actions
from extensions import db, bcrypt
from models.user import User
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS

@@ -9,5 +10,11 @@ def create_app():
    app = Flask(__name__)
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "user_login"


    @login_manager.user_loader
    def load_user(user_id): 
        return User.query.filter_by(id=int(user_id)).first() '''


def create_app():
    app = Flask(__name__)
    CORS(app)
    socketio = SocketIO(app, cors_allowed_origins="*")
    app.register_blueprint(user_bp, url_prefix='/api')
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


