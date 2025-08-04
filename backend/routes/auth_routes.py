from flask import Blueprint, request, jsonify, session
from functools import wraps
from services.auth.firebase_auth import FirebaseAuthService
from flask_socketio import disconnect
from models.user import User
from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import datetime, timezone

auth_bp = Blueprint('auth', __name__)
firebase_auth = FirebaseAuthService()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'status': 'error', 'message': 'No token provided'}), 401
            
        try:
            token = auth_header.split('Bearer ')[1]
            firebase_user = firebase_auth.verify_firebase_token(token)
            request.user = firebase_user
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401
            
    return decorated

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register with Firebase token (supports GitHub OAuth)"""
    try:
        data = request.get_json()
        
        # Check if using Firebase token
        firebase_token = data.get('firebase_token')
        if firebase_token:
            # Firebase registration (including GitHub OAuth)
            firebase_user = firebase_auth.verify_firebase_token(firebase_token)
            user = firebase_auth.get_or_create_user(firebase_user)
            
            # Create session
            session['user_id'] = user.id
            session['authenticated'] = True
            
            return jsonify({
                'status': 'success',
                'message': 'User registered successfully',
                'data': user.to_dict()
            }), 201
        
        # Original email/password registration (keep for backward compatibility)
        required_fields = ['email', 'password', 'username', 'display_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'status': 'error',
                    'message': f'{field} is required'
                }), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        username = data['username'].lower().strip()
        display_name = data['display_name'].strip()
        
        # Check if user already exists
        existing_user = User.query.filter(
            (User.email == email) | (User.username == username)
        ).first()
        
        if existing_user:
            return jsonify({
                'status': 'error',
                'message': 'User already exists'
            }), 409
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(
            email=email,
            username=username,
            display_name=display_name,
            name=display_name,
            password=hashed_password,
            provider='local',
            created_at=datetime.now(timezone.utc)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Create session
        session['user_id'] = new_user.id
        session['authenticated'] = True
        
        return jsonify({
            'status': 'success',
            'message': 'User registered successfully',
            'data': new_user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Registration failed: {str(e)}'
        }), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Login with Firebase token or email/password"""
    try:
        data = request.get_json()
        
        # Check if using Firebase token
        firebase_token = data.get('firebase_token')
        if firebase_token:
            # Firebase login (including GitHub OAuth)
            firebase_user = firebase_auth.verify_firebase_token(firebase_token)
            user = firebase_auth.get_or_create_user(firebase_user)
            
            # Create session
            session['user_id'] = user.id
            session['authenticated'] = True
            
            return jsonify({
                'status': 'success',
                'message': 'Login successful',
                'data': user.to_dict()
            }), 200
        
        # Original email/password login
        if not data.get('email') or not data.get('password'):
            return jsonify({
                'status': 'error',
                'message': 'Email and password are required'
            }), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        
        # Find user by email or username
        user = User.query.filter(
            (User.email == email) | (User.username == email)
        ).first()
        
        if not user or not check_password_hash(user.password, password):
            return jsonify({
                'status': 'error',
                'message': 'Invalid email or password'
            }), 401
        
        # Create session
        session['user_id'] = user.id
        session['authenticated'] = True
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'data': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'Login failed'
        }), 500

@auth_bp.route('/me', methods=['GET'])
def get_current_user():
    """Get current authenticated user info"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                'status': 'error',
                'message': 'Not authenticated'
            }), 401
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 401
        
        return jsonify({
            'status': 'success',
            'data': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'Failed to get user info'
        }), 500

@auth_bp.route('/debug/users', methods=['GET'])
def debug_users():
    """Debug route to check users in database"""
    try:
        users = User.query.all()
        return jsonify({
            'status': 'success',
            'count': len(users),
            'users': [{'id': u.id, 'email': u.email, 'username': u.username} for u in users]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})