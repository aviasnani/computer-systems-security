from app import app, db
from models.user import User
from models.room import Room
from models.message import Message
from models.friend_request import FriendRequest
from models.group import Group
from models.group_member import GroupMember
from models.email import Email

def init_database():
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create a general room if it doesn't exist
        general_room = Room.query.filter_by(id='general').first()
        if not general_room:
            general_room = Room(
                id='general',
                name='General Chat',
                created_by=1
            )
            db.session.add(general_room)
            db.session.commit()
            print("Created general chat room")
        
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_database()