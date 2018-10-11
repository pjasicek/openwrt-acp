import os
from flask_migrate import Migrate
from app import create_app, db
from app.models import User, Role

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
with app.app_context():
    db.create_all()
    user = User.query.filter_by(username=app.config['LOGIN_USERNAME']).first()
    if user is None:
        login_user = User(username=app.config['LOGIN_USERNAME'], password=app.config['LOGIN_PASSWORD'])
        db.session.add(login_user)
    else:
        user.password = app.config['LOGIN_PASSWORD']

    db.session.commit()
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
