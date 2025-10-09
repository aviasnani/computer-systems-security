from extensions import db
from datetime import datetime, timezone 

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Can be plain text or encrypted
    message_type = db.Column(db.String(20), nullable=False, default='text')
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    
    # Encryption fields
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_type = db.Column(db.String(20), nullable=True)  # 'AES', 'RSA', 'hybrid'
    encrypted_aes_key = db.Column(db.Text, nullable=True)  # RSA-encrypted AES key
    iv = db.Column(db.Text, nullable=True)  # Initialization vector for AES
    key_version = db.Column(db.Integer, nullable=True)  # Version of sender's key used

    def to_dict(self):
        return {
            'message_id': self.id,
            'sender_id': self.sender_id,
            'room_id': self.room_id,
            'content': self.content,
            'message_type': self.message_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'is_encrypted': self.is_encrypted,
            'encryption_type': self.encryption_type,
            'encrypted_aes_key': self.encrypted_aes_key,
            'iv': self.iv,
            'key_version': self.key_version
        }
    
    def to_encrypted_dict(self):
        """Return message data for encrypted transmission"""
        return {
            'message_id': self.id,
            'sender_id': self.sender_id,
            'room_id': self.room_id,
            'content': self.content,
            'message_type': self.message_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'is_encrypted': self.is_encrypted,
            'encryption_type': self.encryption_type,
            'encrypted_aes_key': self.encrypted_aes_key,
            'iv': self.iv,
            'key_version': self.key_version
        }