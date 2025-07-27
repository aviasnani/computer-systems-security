from extensions import db
from datetime import datetime, timezone 

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Changed from encrypted_message to content for plain text
    message_type = db.Column(db.String(20), nullable=False, default='text')
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'message_id': self.id,
            'sender_id': self.sender_id,
            'room_id': self.room_id,
            'content': self.content,
            'message_type': self.message_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }