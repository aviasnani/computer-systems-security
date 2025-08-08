import os
import firebase_admin
from datetime import datetime, timezone
from models.user import User
from extensions import db
from firebase_admin import credentials, auth

class FirebaseAuthService:
    def __init__(self):
        self.initialized = False
        self._initialize_firebase()

    def _initialize_firebase(self):
        if not firebase_admin._apps:
            print("DEBUG: Environment variables:")
            print(f"FIREBASE_PROJECT_ID: {os.getenv('FIREBASE_PROJECT_ID')}")
            print(f"FIREBASE_PRIVATE_KEY_ID: {os.getenv('FIREBASE_PRIVATE_KEY_ID')}")
            print(f"FIREBASE_PRIVATE_KEY: {os.getenv('FIREBASE_PRIVATE_KEY')[:50] if os.getenv('FIREBASE_PRIVATE_KEY') else None}...")
            print(f"FIREBASE_CLIENT_EMAIL: {os.getenv('FIREBASE_CLIENT_EMAIL')}")
            print(f"FIREBASE_CLIENT_ID: {os.getenv('FIREBASE_CLIENT_ID')}")
            print(f"FIREBASE_AUTH_URI: {os.getenv('FIREBASE_AUTH_URI')}")
            print(f"FIREBASE_TOKEN_URI: {os.getenv('FIREBASE_TOKEN_URI')}")
            print(f"FIREBASE_AUTH_PROVIDER_x509_CERT_URL: {os.getenv('FIREBASE_AUTH_PROVIDER_x509_CERT_URL')}")
            print(f"FIREBASE_CLIENT_CERT_URL: {os.getenv('FIREBASE_CLIENT_CERT_URL')}")
            cred = credentials.Certificate({
                "type": "service_account",
                "project_id": os.getenv("FIREBASE_PROJECT_ID"),
                "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
                "private_key": os.getenv("FIREBASE_PRIVATE_KEY"),
                "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
                "client_id": os.getenv("FIREBASE_CLIENT_ID"),
                "auth_uri": os.getenv('FIREBASE_AUTH_URI'),
                "token_uri": os.getenv('FIREBASE_TOKEN_URI'),
                "auth_provider_x509_cert_url": os.getenv('FIREBASE_AUTH_PROVIDER_x509_CERT_URL'),
                "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_CERT_URL")
            })
            firebase_admin.initialize_app(cred)
            self.initialized = True
       
        
    def verify_firebase_token(self, id_token):
        try:
            decoded_token = auth.verify_id_token(id_token)
            print(f"DEBUG: Full decoded token: {decoded_token}")
                
            user_info = {
                'uid': decoded_token['uid'],
                'email': decoded_token.get('email'),
                'name': decoded_token.get('name'),
                'picture': decoded_token.get('picture'),
                'firebase': decoded_token.get('firebase')
            }
            
            # Extract GitHub username from email if GitHub OAuth
            email = decoded_token.get('email', '')
            if 'github' in decoded_token.get('firebase', {}).get('sign_in_provider', ''):
                # For GitHub OAuth, use email prefix as username fallback
                github_username = email.split('@')[0] if email else None
                user_info['github_username'] = github_username
                print(f"DEBUG: Extracted GitHub username: {github_username}")

            return user_info
        
        except Exception as e:
            raise ValueError(f"Invalid Firebase token: {str(e)}")

    def extract_github_info(self, firebase_user):
        # Check if user has GitHub username
        github_username = firebase_user.get('github_username')
        if github_username:
            return {
                'username': github_username,
                'user_id': firebase_user.get('github_id', 'unknown'),
                'email': firebase_user.get('email')
            }
        return None
            
    def get_or_create_user(self, firebase_user):
        user = User.query.filter_by(firebase_uid=firebase_user['uid']).first()
        github_info = self.extract_github_info(firebase_user)
        if user:
            # Update existing user
            user.name = firebase_user.get('name', user.name)
            user.profile_picture = firebase_user.get('picture', user.profile_picture)
            user.last_seen = datetime.now(timezone.utc)

            if github_info:
                user.github_username = github_info['username']
                user.github_user_id = github_info['user_id']
                user.provider = 'github'
        else:
            email = firebase_user.get('email')
            if not email:
                raise ValueError("Email is required from Firebase user but not provided.")

            # Generate username from email if no GitHub info
            if github_info and github_info['username']:
                username = github_info['username']
            else:
                username = email.split('@')[0]
            
            print(f"DEBUG: Generated username: {username}")
            
            # Ensure username is unique
            base_username = username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1
                
            print(f"DEBUG: Final username: {username}")

            user = User(
                firebase_uid=firebase_user['uid'],
                email=email,
                username=username,
                name=firebase_user.get('name'),
                display_name=firebase_user.get('name'),
                profile_picture=firebase_user.get('picture'),
                provider='github' if github_info else 'firebase',
                github_username = github_info['username'] if github_info else None,
                github_user_id = github_info['user_id'] if github_info else None,
                last_seen=datetime.now(timezone.utc)
            )
            db.session.add(user)
        
        db.session.commit()
        return user
