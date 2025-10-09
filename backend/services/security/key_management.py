from datetime import datetime
import base64
from models.user import User
from extensions import db

class KeyManagementService:
    @staticmethod
    def validate_public_key(public_key_b64: str) -> bool:
        """
        Basic validation of public key format
        Only checks if it's valid base64 and meets minimum size requirements
        """
        try:
            # Try to decode base64
            key_data = base64.b64decode(public_key_b64)
            
            # Check minimum size (typical RSA public key is at least 162 bytes)
            if len(key_data) < 162:  # Minimum size for 1024-bit RSA public key
                return False
                
            return True
        except Exception:
            return False

    @staticmethod
    def format_public_key_response(user_id: int, public_key_b64: str) -> dict:
        """Format public key data for API response"""
        return {
            'user_id': user_id,
            'public_key': public_key_b64
        }

    @staticmethod
    def store_public_key(user_id: int, public_key_b64: str) -> dict:
        """
        Store user's public key in database
        """
        if not KeyManagementService.validate_public_key(public_key_b64):
            raise ValueError("Invalid public key format")
        
        try:
            # Get user from database
            user = User.query.get(user_id)
            if not user:
                raise ValueError(f"User {user_id} not found")
            
            # Update user's public key
            user.public_key = public_key_b64
            user.key_version += 1
            user.created_at = datetime.utcnow()
            
            db.session.commit()
            
            return {
                'user_id': user_id,
                'public_key': public_key_b64,
                'created_at': user.created_at.isoformat(),
                'key_version': user.key_version
            }
        except Exception as e:
            db.session.rollback()
            raise ValueError(f"Failed to store public key: {str(e)}")

    @staticmethod
    def get_public_key(user_id: int) -> str:
        """
        Retrieve user's public key from database
        """
        try:
            user = User.query.get(user_id)
            if not user:
                raise ValueError(f"User {user_id} not found")
            
            if not user.public_key:
                raise ValueError(f"No public key available for user {user_id}")
            
            return user.public_key
        except Exception as e:
            raise ValueError(f"Failed to retrieve public key: {str(e)}")
    
    @staticmethod
    def get_public_key_with_metadata(user_id: int) -> dict:
        """
        Retrieve user's public key with metadata from database
        """
        try:
            user = User.query.get(user_id)
            if not user:
                raise ValueError(f"User {user_id} not found")
            
            if not user.public_key:
                raise ValueError(f"No public key available for user {user_id}")
            
            return {
                'user_id': user.id,
                'public_key': user.public_key,
                'key_version': user.key_version,
                'created_at': user.created_at.isoformat() if user.created_at else None
            }
        except Exception as e:
            raise ValueError(f"Failed to retrieve public key: {str(e)}")
    
    @staticmethod
    def get_multiple_public_keys(user_ids: list) -> dict:
        """
        Retrieve public keys for multiple users
        """
        try:
            users = User.query.filter(User.id.in_(user_ids)).all()
            result = {}
            
            for user in users:
                if user.public_key:
                    result[user.id] = {
                        'public_key': user.public_key,
                        'key_version': user.key_version,
                        'created_at': user.created_at.isoformat() if user.created_at else None
                    }
            
            return result
        except Exception as e:
            raise ValueError(f"Failed to retrieve public keys: {str(e)}") 