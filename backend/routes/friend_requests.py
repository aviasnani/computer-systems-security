from flask import Blueprint, jsonify, request
from models.user import User
from models.friend_request import FriendRequest
from routes.auth_routes import require_auth
from extensions import db
from datetime import datetime, timezone

friend_bp = Blueprint('friends', __name__)

@friend_bp.route('/friends', methods=['GET'])
@require_auth
def get_friends():
    """Get current user's friends list"""
    try:
        # Get current user from session
        current_user = User.query.get(request.user['id'])
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Get accepted friend requests where current user is either sender or receiver
        friends = []
        
        # Friends where current user is the sender
        sent_requests = FriendRequest.query.filter_by(
            sender_id=current_user.id,
            status='accepted'
        ).all()
        
        for req in sent_requests:
            friend = User.query.get(req.receiver_id)
            if friend:
                friends.append({
                    'id': friend.id,
                    'name': friend.name,
                    'email': friend.email,
                    'username': friend.username
                })
        
        # Friends where current user is the receiver
        received_requests = FriendRequest.query.filter_by(
            receiver_id=current_user.id,
            status='accepted'
        ).all()
        
        for req in received_requests:
            friend = User.query.get(req.sender_id)
            if friend:
                friends.append({
                    'id': friend.id,
                    'name': friend.name,
                    'email': friend.email,
                    'username': friend.username
                })
        
        return jsonify({
            'status': 'success',
            'friends': friends
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@friend_bp.route('/friends/requests', methods=['GET'])
@require_auth
def get_pending_requests():
    """Get pending friend requests for current user"""
    try:
        # Get current user from session
        current_user = User.query.get(request.user['id'])
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Get pending requests where current user is the receiver
        pending_requests = FriendRequest.query.filter_by(
            receiver_id=current_user.id,
            status='pending'
        ).all()
        
        requests_data = []
        for req in pending_requests:
            sender = User.query.get(req.sender_id)
            if sender:
                requests_data.append({
                    'id': req.id,
                    'sender_id': sender.id,
                    'sender_name': sender.name,
                    'sender_email': sender.email,
                    'sender_username': sender.username,
                    'created_at': req.created_at.isoformat() if req.created_at else None
                })
        
        return jsonify({
            'status': 'success',
            'requests': requests_data
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@friend_bp.route('/friends/request', methods=['POST'])
@require_auth
def send_friend_request():
    """Send a friend request"""
    try:
        data = request.get_json()
        target_email = data.get('target_email') or data.get('email')
        target_user_id = data.get('target_user_id')
        
        if not target_email and not target_user_id:
            return jsonify({'status': 'error', 'message': 'target_email or target_user_id is required'}), 400
        
        # Get current user from session
        current_user = User.query.get(request.user['id'])
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Find target user by email or ID
        if target_email:
            target_user = User.query.filter_by(email=target_email).first()
        else:
            target_user = User.query.get(target_user_id)
            
        if not target_user:
            return jsonify({'status': 'error', 'message': 'Target user not found'}), 404
        
        if target_user.id == current_user.id:
            return jsonify({'status': 'error', 'message': 'Cannot send request to yourself'}), 400
        
        # Check if request already exists
        existing_request = FriendRequest.query.filter(
            ((FriendRequest.sender_id == current_user.id) & (FriendRequest.receiver_id == target_user.id)) |
            ((FriendRequest.sender_id == target_user.id) & (FriendRequest.receiver_id == current_user.id))
        ).first()
        
        if existing_request:
            if existing_request.status == 'pending':
                return jsonify({'status': 'error', 'message': 'Friend request already pending'}), 400
            elif existing_request.status == 'accepted':
                return jsonify({'status': 'error', 'message': 'Already friends'}), 400
        
        # Create new friend request
        friend_request = FriendRequest(
            sender_id=current_user.id,
            receiver_id=target_user.id,
            status='pending',
            created_at=datetime.now(timezone.utc)
        )
        
        db.session.add(friend_request)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Friend request sent successfully'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@friend_bp.route('/friends/accept/<int:request_id>', methods=['POST'])
@require_auth
def accept_friend_request(request_id):
    """Accept a friend request"""
    try:
        # Get current user
        current_user = User.query.filter_by(firebase_uid=request.user['uid']).first()
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Get the friend request
        friend_request = FriendRequest.query.get(request_id)
        if not friend_request:
            return jsonify({'status': 'error', 'message': 'Friend request not found'}), 404
        
        # Check if current user is the receiver
        if friend_request.receiver_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
        
        # Check if request is pending
        if friend_request.status != 'pending':
            return jsonify({'status': 'error', 'message': 'Request is not pending'}), 400
        
        # Accept the request
        friend_request.status = 'accepted'
        friend_request.updated_at = datetime.now(timezone.utc)
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Friend request accepted'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@friend_bp.route('/friends/reject/<int:request_id>', methods=['POST'])
@require_auth
def reject_friend_request(request_id):
    """Reject a friend request"""
    try:
        # Get current user
        current_user = User.query.filter_by(firebase_uid=request.user['uid']).first()
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Get the friend request
        friend_request = FriendRequest.query.get(request_id)
        if not friend_request:
            return jsonify({'status': 'error', 'message': 'Friend request not found'}), 404
        
        # Check if current user is the receiver
        if friend_request.receiver_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
        
        # Check if request is pending
        if friend_request.status != 'pending':
            return jsonify({'status': 'error', 'message': 'Request is not pending'}), 400
        
        # Reject the request
        friend_request.status = 'rejected'
        friend_request.updated_at = datetime.now(timezone.utc)
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Friend request rejected'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@friend_bp.route('/friends/remove/<int:friend_id>', methods=['DELETE'])
@require_auth
def remove_friend(friend_id):
    """Remove a friend"""
    try:
        # Get current user
        current_user = User.query.filter_by(firebase_uid=request.user['uid']).first()
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Find the friend relationship
        friend_request = FriendRequest.query.filter(
            ((FriendRequest.sender_id == current_user.id) & (FriendRequest.receiver_id == friend_id)) |
            ((FriendRequest.sender_id == friend_id) & (FriendRequest.receiver_id == current_user.id)),
            FriendRequest.status == 'accepted'
        ).first()
        
        if not friend_request:
            return jsonify({'status': 'error', 'message': 'Friend relationship not found'}), 404
        
        # Remove the friendship
        db.session.delete(friend_request)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Friend removed successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@friend_bp.route('/users/search', methods=['GET'])
@require_auth
def search_users():
    """Search for users by email or username"""
    try:
        query = request.args.get('q', '').strip()
        if not query:
            return jsonify({'status': 'error', 'message': 'Search query is required'}), 400
        
        # Get current user
        current_user = User.query.filter_by(firebase_uid=request.user['uid']).first()
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Search for users
        users = User.query.filter(
            (User.email.contains(query) | User.username.contains(query) | User.name.contains(query)),
            User.id != current_user.id
        ).limit(10).all()
        
        users_data = []
        for user in users:
            users_data.append({
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'username': user.username
            })
        
        return jsonify({
            'status': 'success',
            'users': users_data
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500