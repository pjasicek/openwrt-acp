import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    LOGIN_USERNAME = os.environ.get('LOGIN_USERNAME') or 'admin'
    LOGIN_PASSWORD = os.environ.get('LOGIN_PASSWORD') or 'admin'

    OPENWRT_USERNAME = os.environ.get('OPENWRT_USERNAME') or 'root'
    OPENWRT_PASSWORD = os.environ.get('OPENWRT_PASSWORD') or 'root'
    OPENWRT_SSH_KEYFILE = os.environ.get('OPENWRT_SSH_KEYFILE') or os.path.abspath('data/openwrt_key.priv')

    OPENWRT_NETWORK = os.environ.get('OPENWRT_NETWORK') or '192.168.1.0/24'

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
                              'sqlite://'


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'data.sqlite')


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig
}
