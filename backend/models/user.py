from datetime import datetime, timezone
from extensions import db
from flask_login import UserMixin


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True) 
    name = db.Column(db.String(50), nullable=True)  
    email = db.Column(db.String(120), unique=True, nullable=False)  
    date_of_birth = db.Column(db.Date, nullable=True) 
    username = db.Column(db.String(30), unique=True, nullable=False)  
    password = db.Column(db.String(128), nullable=True)  
    public_key = db.Column(db.Text, nullable=True)  
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)) 
    provider = db.Column(db.String(20), nullable=False, default='manual')

    #firebase user info
    firebase_uid = db.Column(db.String(128), unique=True, nullable=True)
    profile_picture = db.Column(db.String(255))
    last_seen = db.Column(db.DateTime(timezone=True))

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'profile_picture': self.profile_picture,
            'created_at': self.created_at.isoformat(),
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }
