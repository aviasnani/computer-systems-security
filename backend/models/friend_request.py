from extensions import db
from datetime import datetime, timezone

class FriendRequest(db.Model):
  id = db.Column(db.Integer, primary_key=True, nullable=False)
  from_user = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  to_user = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  joined_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


