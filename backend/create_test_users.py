from app import app
from extensions import db, bcrypt
from models.user import User

def create_test_users():
    with app.app_context():
        # Create test users
        test_users = [
            {'username': 'alice', 'email': 'alice@example.com', 'name': 'Alice Smith'},
            {'username': 'bob', 'email': 'bob@example.com', 'name': 'Bob Johnson'},
            {'username': 'charlie', 'email': 'charlie@example.com', 'name': 'Charlie Brown'},
        ]
        
        for user_data in test_users:
            # Check if user already exists
            existing_user = User.query.filter_by(username=user_data['username']).first()
            if not existing_user:
                # Hash password
                password_hash = bcrypt.generate_password_hash('password123').decode('utf-8')
                
                user = User(
                    username=user_data['username'],
                    email=user_data['email'],
                    name=user_data['name'],
                    password=password_hash
                )
                db.session.add(user)
                print(f"Created user: {user_data['username']}")
            else:
                print(f"User {user_data['username']} already exists")
        
        db.session.commit()
        print("Test users created successfully!")

if __name__ == '__main__':
    create_test_users()