#!/usr/bin/env python3
"""
Test database operations
"""

from app import app
from extensions import db
from models.user import User
from datetime import datetime, timezone

def test_user_creation():
    with app.app_context():
        print("Testing user creation...")
        
        # Check current user count
        user_count = User.query.count()
        print(f"Current users in DB: {user_count}")
        
        # Create a test user
        test_user = User(
            email='test@example.com',
            username='testuser',
            display_name='Test User',
            name='Test User',
            password='hashed_password',
            provider='local',
            created_at=datetime.now(timezone.utc)
        )
        
        try:
            db.session.add(test_user)
            db.session.commit()
            print(f"✅ User created with ID: {test_user.id}")
            
            # Verify user exists
            found_user = User.query.filter_by(email='test@example.com').first()
            if found_user:
                print(f"✅ User found in DB: {found_user.email}")
            else:
                print("❌ User not found in DB")
                
        except Exception as e:
            print(f"❌ Error creating user: {e}")
            db.session.rollback()

if __name__ == '__main__':
    test_user_creation()