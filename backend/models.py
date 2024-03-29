import random
import string
import time
import datetime

import bcrypt
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def generate_token():
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(10))


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    value = db.Column(db.String(10), nullable=False, default=generate_token, unique=True)
    issue_time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    def is_valid(self, secs):
        if (datetime.datetime.now()-self.issue_time).total_seconds() < int(secs):
            return True
        else:
            return False

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String, unique=True)
    email = db.Column(db.String, unique=True)
    name = db.Column(db.String, nullable=True)
    surname = db.Column(db.String, nullable=True)
    password = db.Column(db.LargeBinary, nullable=True)
    isAdmin = db.Column(db.Boolean, default=False, nullable=True)

    def gen_password(password):
        return bcrypt.hashpw(bytes(password, encoding="utf-8"), bcrypt.gensalt())

    def __str__(self):
        return self.username

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return bcrypt.hashpw(bytes(password, encoding="utf-8"), bcrypt.gensalt()) == self.password


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth2_code'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        # It will expire after a month.
        expires_at = self.issued_at + 2628000 * 2
        return expires_at >= time.time()
