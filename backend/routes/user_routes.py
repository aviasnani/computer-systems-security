from flask import Blueprint, jsonify, request
from models.user import User
from services.security.key_management import KeyManagementService
from routes.auth_routes import require_auth

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