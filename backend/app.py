from flask import Flask, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
from config.config import Config
from extensions import db
from routes.user_routes import user_bp
from routes.auth_routes import auth_bp
from routes.friend_requests import friend_bp
from services.messaging.socket_handler import SocketHandler

app = Flask(__name__)
app.config.from_object(Config)

CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize extensions
db.init_app(app)

# Register blueprints
app.register_blueprint(user_bp, url_prefix='/api')
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(friend_bp, url_prefix='/api/friends')

# Initialize socket handler
socket_handler = SocketHandler(socketio)

@app.route('/')
def index():
    return jsonify({"status": "ok", "message": "Server is running"})

@app.route('/test-auth')
def test_auth():
    from flask import session
    if session.get('authenticated'):
        return jsonify({"status": "ok", "message": "Authenticated", "user_id": session.get('user_id')})
    else:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

# Export for run.py
__all__ = ['app', 'socketio']


