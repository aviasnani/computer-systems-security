from flask import Blueprint, request, jsonify, session
from functools import wraps
from services.auth.firebase_auth import FirebaseAuthService
from flask_socketio import disconnect

auth_bp = Blueprint('auth', __name__)
firebase_auth = FirebaseAuthService()
#authorization header is used to authenticate the user
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

@auth_bp.route('/check', methods=['GET'])
@require_auth
def check_auth():
    """Check if user is authenticated"""
    return jsonify({
        'status': 'success',
        'authenticated': True,
        'user': request.user
    }) 