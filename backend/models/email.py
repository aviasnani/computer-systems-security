from extensions import db
from datetime import datetime, timezone 

class Email(db.Model):
  id = db.Column(db.Integer, primary_key=True, nullable=False)
  to_user = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  email_type = db.Column(db.String(20), nullable=False)
  timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))