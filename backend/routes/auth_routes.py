from flask import Blueprint, request, jsonify, session
from functools import wraps
from services.auth.firebase_auth import FirebaseAuthService
from flask_socketio import disconnect
from models.user import User
from extensions import db, bcrypt
from datetime import datetime, timezone

auth_bp = Blueprint('auth', __name__)
firebase_auth = FirebaseAuthService()

#authorization header is used to authenticate the user
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check if user is authenticated via session
        if not session.get('authenticated') or not session.get('user_id'):
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
            
        try:
            # Get user from database
            user = User.query.get(session['user_id'])
            if not user:
                return jsonify({'status': 'error', 'message': 'User not found'}), 404
            
            # Add user info to request
            request.user = {
                'uid': user.firebase_uid,
                'id': user.id,
                'email': user.email,
                'name': user.name
            }
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'status': 'error', 'message': 'Authentication failed'}), 401
            
    return decorated

#Frontend sends firebase token to this route make sure 
@auth_bp.route('/firebase', methods=['POST'])
def firebase_auth_handler():
    """Handle Firebase authentication and create+update user in our system"""
    try:
        data = request.get_json()
        if not data or 'firebaseToken' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Firebase token is required'
            }), 400

        firebase_user = firebase_auth.verify_firebase_token(data['firebaseToken'])
        
        user = firebase_auth.get_or_create_user(firebase_user)
        
        session['user_id'] = user.id
        session['firebase_uid'] = firebase_user['uid']
        session['authenticated'] = True
        
        return jsonify({
            'status': 'success',
            'data': {
                'user_id': user.id,
                'email': user.email,
                'username': user.username,
                'profile_picture': user.profile_picture
            }
        }), 200

    except ValueError as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 401
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'Authentication failed'
        }), 500

@auth_bp.route('/signup', methods=['POST'])
def manual_signup():
    """Manual user registration"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        username = data.get('username')
        
        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password required'}), 400
            
        # Check if user exists
        if User.query.filter_by(email=email).first():
            return jsonify({'status': 'error', 'message': 'User already exists'}), 400
            
        # Generate username if not provided
        if not username:
            username = email.split('@')[0]
            
        # Check if username is taken
        if User.query.filter_by(username=username).first():
            username = f"{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Create user
        user = User(
            email=email,
            username=username,
            name=name or email.split('@')[0],
            password=hashed_password,
            firebase_uid=f'manual_{email}',
            provider='manual'
        )
        
        db.session.add(user)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': f'Database error: {str(e)}'}), 500
        
        return jsonify({
            'status': 'success',
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'username': user.username
            }
        }), 201
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def manual_login():
    """Manual user login"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password required'}), 400
            
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
            
        # Verify password
        if not bcrypt.check_password_hash(user.password, password):
            return jsonify({'status': 'error', 'message': 'Invalid password'}), 401
            
        # Update last seen
        user.last_seen = datetime.now(timezone.utc)
        db.session.commit()
            
        # Set session
        session['user_id'] = user.id
        session['firebase_uid'] = user.firebase_uid
        session['authenticated'] = True
        
        return jsonify({
            'status': 'success',
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'username': user.username,
                'uid': user.firebase_uid
            }
        }), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@auth_bp.route('/check', methods=['GET'])
@require_auth
def check_auth():
    """Check if user is authenticated"""
    return jsonify({
        'status': 'success',
        'authenticated': True,
        'user': request.user
    }) 