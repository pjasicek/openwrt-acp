import os
from gevent import monkey
monkey.patch_all()
from flask_migrate import Migrate
from app import create_app, db, socketio
from app.models import User, Role, Openwrt, GlobalState, Network, WirelessNetwork
from app.main import openwrt_api
from time import sleep
from threading import Thread

import json
from pprint import pprint


app = create_app(os.getenv('FLASK_CONFIG') or 'default')

# Import environment variables
if os.path.exists('.env'):
    print('Importing environment from .env...')
    for line in open('.env'):
        var = line.strip().split('=')
        if len(var) == 2:
            os.environ[var[0]] = var[1]

# Create default DB entries
# with app.app_context():
#     db.create_all()
#     user = User.query.filter_by(username=app.config['LOGIN_USERNAME']).first()
#     if user is None:
#         login_user = User(username=app.config['LOGIN_USERNAME'], password=app.config['LOGIN_PASSWORD'])
#         db.session.add(login_user)
#     else:
#         user.password = app.config['LOGIN_PASSWORD']
#
#     db.session.commit()
with app.app_context():
    db.drop_all()
    db.create_all()

    login_user = User(username=app.config['LOGIN_USERNAME'], password=app.config['LOGIN_PASSWORD'])
    db.session.add(login_user)

    global_state = GlobalState()
    db.session.add(global_state)

    with open('data/openwrts.json') as openwrtJsonFile:
        openwrtsJson = json.load(openwrtJsonFile)

    for openwrtJson in openwrtsJson["openwrts"]:
        openwrt = Openwrt(name=openwrtJson["name"], ip_address=openwrtJson["ip_address"])
        db.session.add(openwrt)

    with open('data/networks_default.json') as networksJsonFile:
        networksJson = json.load(networksJsonFile)

    for networkJson in networksJson["networks"]:
        network = Network(name=networkJson["name"],
                          purpose=networkJson["purpose"],
                          network_addr=networkJson["network_addr"],
                          gateway=networkJson["gateway"],
                          vlan=networkJson["vlan"],
                          is_dhcp_mode=networkJson["is_dhcp_mode"],
                          dhcp_range_from=networkJson["dhcp_range_from"],
                          dhcp_range_to=networkJson["dhcp_range_to"],
                          dhcp_lease_time=networkJson["dhcp_lease_time"])
        db.session.add(network)

    with open('data/ssid_default.json') as wirelessNetworksJsonFile:
        ssidsJson = json.load(wirelessNetworksJsonFile)

    for ssidJson in ssidsJson["ssids"]:
        ssid = WirelessNetwork(ssid=ssidJson["ssid"],
                          enabled=ssidJson["enabled"],
                          security_type=ssidJson["security_type"],
                          password=ssidJson["password"],
                          is_vlan=ssidJson["is_vlan"],
                          vlan=ssidJson["vlan"],
                          network=ssidJson["network"])
        db.session.add(ssid)

    db.session.commit()


# Background refresh thread
def background_refresh_job(app):
    while True:
        # Every 5 minutes
        sleep(5 * 60)

        # Get lock
        if openwrt_api.test_and_set_refresh() is True:
            print('Spawning refresh_all_openwrts job ...')
            # Refresh OpenWRTs in background
            thr = Thread(target=openwrt_api.refresh_all_openwrts, args=[app])
            thr.start()


refresh_thread = Thread(target=background_refresh_job, args=[app])
refresh_thread.setDaemon(True)
refresh_thread.start()

migrate = Migrate(app, db)


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role)


@app.cli.command()
def test():
    """Run the unit tests."""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)


if __name__ == '__main__':
    socketio.run(app, debug=True, threaded=True)
