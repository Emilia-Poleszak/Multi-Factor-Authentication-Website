from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    webauthn_id = db.Column(db.Integer, unique=True, nullable=True)
    webauthn_public_key = db.Column(db.Text)

    totp_secret = db.Column(db.String(128), nullable=False)

    def __init__(self, username, email, password_hash, webauthn_id, webauthn_public_key, totp_secret):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.webauthn_id = webauthn_id
        self.webauthn_public_key = webauthn_public_key
        self.totp_secret = totp_secret
