from flask import Blueprint, jsonify, request
from models.friend_request import FriendRequest
from models.user import User
from extensions import db
from routes.auth_routes import require_auth

friend_bp = Blueprint('friends', __name__)

@friend_bp.route('/send', methods=['POST'])
@require_auth
def send_friend_request():
    """Send a friend request"""
    try:
        data = request.get_json()
        to_user_id = data.get('to_user_id')
        
        if not to_user_id:
            return jsonify({'status': 'error', 'message': 'User ID required'}), 400
            
        # Check if user exists
        to_user = User.query.get(to_user_id)
        if not to_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
            
        # Create friend request
        friend_request = FriendRequest(
            from_user=request.user['uid'],
            to_user=to_user_id
        )
        
        db.session.add(friend_request)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Friend request sent'}), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500