from flask import Blueprint, jsonify, request
from models.user import User
from services.security.key_management import KeyManagementService
from routes.auth_routes import require_auth
from extensions import db
from services.messaging.room_manager import RoomManager

user_bp = Blueprint('user', __name__)

@user_bp.route('/users/<int:user_id>/public-key', methods=['GET'])
@require_auth
def get_public_key(user_id):
    """Get user's public key (requires authentication)"""
    try:
        # Verify the user is authenticated
        if not request.user:
            return jsonify({
                'status': 'error',
                'message': 'Authentication required'
            }), 401

        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
            
        if not user.public_key:
            return jsonify({
                'status': 'error',
                'message': 'No public key available for this user'
            }), 404

        # Validate publickey format
        if not KeyManagementService.validate_public_key(user.public_key):
            return jsonify({
                'status': 'error',
                'message': 'Invalid public key format'
            }), 500

        return jsonify({
            'status': 'success',
            'data': {
                'user_id': user.id,
                'public_key': user.public_key,
                'key_version': user.key_version,
                'created_at': user.created_at.isoformat()
            }
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500 

@user_bp.route('/public-key', methods=['POST'])
@require_auth
def store_public_key():
    try:
        data = request.get_json()
        if not data or 'publicKey' not in data:
            return jsonify({'status': 'error', 'message': 'publicKey required'}), 400
            
        user = User.query.filter_by(firebase_uid=request.user['uid']).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
            
        # Use the key management service to store the key
        result = KeyManagementService.store_public_key(user.id, data['publicKey'])
        
        return jsonify({
            'status': 'success',
            'data': result
        })
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@user_bp.route('/users/online', methods=['GET'])
@require_auth
def get_online_users():
    """Get list of online users for key exchange"""
    try:
        # Get current user
        current_user = User.query.filter_by(firebase_uid=request.user['uid']).first()
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Get all users with public keys (simplified - in real app you'd track online status)
        users = User.query.filter(User.public_key.isnot(None)).all()
        
        online_users = []
        for user in users:
            if user.id != current_user.id:  # Exclude current user
                online_users.append({
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'has_public_key': bool(user.public_key),
                    'key_version': user.key_version,
                    'last_seen': user.last_seen.isoformat() if user.last_seen else None
                })
        
        return jsonify({
            'status': 'success',
            'data': {
                'online_users': online_users,
                'current_user_id': current_user.id
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@user_bp.route('/users/<int:user_id>/request-key', methods=['POST'])
@require_auth
def request_user_key(user_id):
    """Request a specific user's public key"""
    try:
        # Get current user
        current_user = User.query.filter_by(firebase_uid=request.user['uid']).first()
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Get target user's public key
        try:
            key_data = KeyManagementService.get_public_key_with_metadata(user_id)
            return jsonify({
                'status': 'success',
                'data': key_data
            }), 200
        except ValueError as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 404
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@user_bp.route('/users/batch-keys', methods=['POST'])
@require_auth
def get_multiple_keys():
    """Get public keys for multiple users at once"""
    try:
        data = request.get_json()
        if not data or 'user_ids' not in data:
            return jsonify({'status': 'error', 'message': 'user_ids array required'}), 400
        
        user_ids = data['user_ids']
        if not isinstance(user_ids, list):
            return jsonify({'status': 'error', 'message': 'user_ids must be an array'}), 400
        
        # Get keys for multiple users
        keys_data = KeyManagementService.get_multiple_public_keys(user_ids)
        
        return jsonify({
            'status': 'success',
            'data': keys_data
        }), 200
        
    except ValueError as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500