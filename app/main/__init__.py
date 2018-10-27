from flask import Blueprint
from .openwrt_api import OpenwrtApi

main = Blueprint('main', __name__)
openwrt_api = OpenwrtApi()

from . import views, errors