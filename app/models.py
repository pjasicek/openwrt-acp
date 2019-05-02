from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import db, login_manager
from flask_jsontools import JsonSerializableBase
from sqlalchemy.ext.declarative import declarative_base
from threading import Lock

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
    comment = db.Column(db.String(256), default="")
    channel = db.Column(db.String(32), default="-")
    eth0_mac = db.Column(db.String(64), default="")

    def __repr__(self):
        return '<OpenWRT %r>' % self.name


class OpenwrtComments(db.Model, Base):
    __tablename__ = 'openwrt_comments'
    id = db.Column(db.String(64), primary_key=True)  # eth0 MAC address
    comment = db.Column(db.String(256), default="")


class Network(db.Model, Base):
    __tablename__ = 'networks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    network_addr = db.Column(db.String(32), unique=True, nullable=False)
    gateway = db.Column(db.String(32), nullable=False)
    vlan = db.Column(db.Integer, default="")
    configure_gateway = db.Column(db.Boolean, default=False)
    is_dhcp_mode = db.Column(db.Boolean, default=True)
    dhcp_range_from = db.Column(db.String(32), unique=True)
    dhcp_range_to = db.Column(db.String(32), unique=True)
    dhcp_lease_time = db.Column(db.Integer, default=86400)

    def __repr__(self):
        return '<Network %r>' % self.name


class WirelessNetwork(db.Model, Base):
    __tablename__ = 'wireless_networks'
    id = db.Column(db.Integer, primary_key=True)
    ssid = db.Column(db.String(64), unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    security_type = db.Column(db.String(64), default="Open")
    password = db.Column(db.String(128), default="")
    network = db.Column(db.String(128), default="")
    vlan = db.Column(db.Integer, default=0)
    hide_ssid = db.Column(db.Boolean, default=False)
    isolate_clients = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<WirelessNetwork %r>' % self.ssid


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
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
