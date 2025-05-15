from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone = db.Column(db.String(15))
    role = db.Column(db.String(20), default='user')
    #vendor_id = db.Column(db.Integer, ForeignKey('vendor.id'), nullable=True)
    bids = db.relationship('Bid', backref='user', lazy=True)
    #vendor = relationship('Vendor', backref='users')

    def __repr__(self):
        return f"<User {self.username}, Role: {self.role}>"

class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    addr = db.Column(db.String(50), nullable=False)


    #bids = db.relationship('Bid', backref='vendor', lazy=True)

    def __repr__(self):
        return f"<Vendor {self.first_name} {self.last_name}>"

class Tender(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50),nullable=False)
    price = db.Column(db.Integer,nullable=False)
    description = db.Column(db.Text, nullable=False)
    deadline = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    bids = db.relationship('Bid', backref='tender', lazy=True)
    user = db.relationship('User', backref='tenders')
    notices = db.relationship('Notice', backref='tender', lazy=True)

    def __repr__(self):
        return f"<Tender {self.title}>"

class Bid(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey('tender.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # e.g. 'pending', 'accepted', 'rejected'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Bid by {self.user.username} for Tender {self.tender.title}>"

class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey('tender.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Notice for Tender {self.tender.title}: {self.message}>"
