import os
from models.user import User
from extensions import db

class FirebaseAuthService:
    def __init__(self):
        # For development, we'll skip Firebase admin initialization
        # In production, you would initialize with proper credentials
        self.initialized = False
        
    def verify_firebase_token(self, id_token):
        """Mock Firebase token verification for development"""
        # In development, we'll create a mock user from the token
        # In production, you would use firebase_admin.auth.verify_id_token(id_token)
        try:
            # Mock decoded token structure
            return {
                'uid': 'mock_uid_' + id_token[:10],
                'email': 'user@example.com',
                'name': 'Test User',
                'picture': None
            }
        except Exception as e:
            raise ValueError(f"Invalid Firebase token: {str(e)}")

    def get_or_create_user(self, firebase_user):
        """Get existing user or create new one"""
        user = User.query.filter_by(firebase_uid=firebase_user['uid']).first()
        
        if not user:
            # Create new user
            user = User(
                firebase_uid=firebase_user['uid'],
                email=firebase_user.get('email'),
                username=firebase_user.get('name', 'User'),
                name=firebase_user.get('name'),
                profile_picture=firebase_user.get('picture')
            )
            db.session.add(user)
            db.session.commit()
        
        return user 