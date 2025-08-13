from extensions import db
from datetime import datetime, timezone

class GroupMember(db.Model):
  id = db.Column(db.Integer, primary_key=True, nullable=False)
  member_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
  joined_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

