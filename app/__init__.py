from gevent import monkey
monkey.patch_all()

from flask import Flask
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from config import config
# import redis
# import aioredis
#import socketio as socketio_

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
socketio = SocketIO(async_mode="gevent", async_handlers=True, logger=True, engineio_logger=True)
# mgr = socketio_.RedisManager('redis://')
# sio = socketio_.Server(client_manager=mgr)
# mgr = socketio_.AsyncRedisManager('redis://')
# sio = socketio_.AsyncServer(client_manager=mgr)

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'
login_manager.login_message = None


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app, async_mode="gevent", async_handlers=True, logger=True, engineio_logger=True)

    from .main import openwrt_api as api
    api.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    return app