from flask import Blueprint, jsonify, request, session
from models.user import User
from extensions import db
import traceback

user_bp = Blueprint('user', __name__)

@user_bp.route('/test', methods=['GET'])
def test_route():
    return jsonify({'status': 'success', 'message': 'User routes working'})

@user_bp.route('/users/<int:user_id>/public-key', methods=['GET'])
def get_public_key(user_id):
    try:
        # Temporarily disable auth check for testing
        # if not session.get('user_id'):
        #     return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401

        user = User.query.get(user_id)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        # If user doesn't have a public key, return 404
        if not user.public_key:
            return jsonify({
                'status': 'error', 
                'message': 'No public key available'
            }), 404

        return jsonify({
            'status': 'success',
            'data': {
                'user_id': user.id,
                'public_key': user.public_key,
                'key_version': getattr(user, 'key_version', 1)
            }
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@user_bp.route('/users/<int:user_id>/public-key', methods=['POST'])
def update_public_key(user_id):
    try:
        print(f"[DEBUG] Public key upload for user {user_id}")
        print(f"[DEBUG] Session: {dict(session)}")
        print(f"[DEBUG] Headers: {dict(request.headers)}")
        
        # Temporarily disable auth check for testing
        # if not session.get('user_id'):
        #     return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401

        data = request.get_json()
        print(f"[DEBUG] Request data: {data}")
        
        if not data or 'public_key' not in data:
            return jsonify({'status': 'error', 'message': 'Public key required'}), 400

        public_key = data['public_key']
        if not public_key.startswith('-----BEGIN PUBLIC KEY-----'):
            return jsonify({'status': 'error', 'message': 'Invalid key format'}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        user.public_key = public_key
        user.key_version = getattr(user, 'key_version', 0) + 1
        db.session.commit()
        
        print(f"[DEBUG] Key updated successfully for user {user_id}")
        return jsonify({
            'status': 'success',
            'data': {'user_id': user.id, 'message': 'Key updated'}
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] {str(e)}")
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@user_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        return jsonify({
            'status': 'success',
            'data': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'display_name': user.display_name or user.name or user.username,
                'name': user.name,
                'github_username': user.github_username,
                'is_online': user.is_online,
                'last_seen': user.last_seen.isoformat() if user.last_seen else None
            }
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@user_bp.route('/users', methods=['GET'])
def get_all_users():
    try:
        users = User.query.all()
        return jsonify({
            'status': 'success',
            'data': [{
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'display_name': user.display_name or user.name or user.username,
                'name': user.name or user.username,
                'github_username': user.github_username,
                'has_public_key': False
            } for user in users]
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@user_bp.route('/users/search', methods=['GET'])
def search_users():
    try:
        query = request.args.get('q', '').strip()
        if not query:
            return jsonify({'status': 'error', 'message': 'Query required'}), 400

        users = User.query.filter(
            (User.username.ilike(f'%{query}%')) | 
            (User.email.ilike(f'%{query}%'))
        ).limit(10).all()

        return jsonify({
            'status': 'success',
            'data': [{
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'display_name': user.display_name or user.name or user.username,
                'name': user.name or user.username,
                'github_username': user.github_username,
                'has_public_key': False
            } for user in users]
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500 