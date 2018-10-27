from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import db, login_manager
from flask_jsontools import JsonSerializableBase
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base(cls=(JsonSerializableBase,))


class Openwrt(db.Model, Base):
    __tablename__ = 'openwrts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    ip_address = db.Column(db.String(32), unique=True, nullable=False)
    ping = db.Column(db.Boolean, default=False)
    luci = db.Column(db.Boolean, default=False)
    ssh = db.Column(db.Boolean, default=False)
    hostname = db.Column(db.String(64), default="-")
    firmware = db.Column(db.String(128), default="-")
    uptime = db.Column(db.String(64), default="-")
    clients = db.Column(db.String(64), default="-")
    down = db.Column(db.String(64), default="-")
    up = db.Column(db.String(64), default="-")
    comment = db.Column(db.String(256), default="")

    # These data are for OpenWRT update
    update_in_progress = db.Column
    auth_token = db.Column(db.String(32), default="none")

    def __repr__(self):
        return '<OpenWRT %r>' % self.name


# Sorry
class GlobalState(db.Model):
    __tablename__ = 'globalstate'
    id = db.Column(db.Integer, primary_key=True)
    last_scan = db.Column(db.DateTime)
    is_scanning = db.Column(db.Boolean, default=False)


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))