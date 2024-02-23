import os
from flask import Flask
from backend.models import db, User
from backend.oauth2 import config_oauth
from backend.routes import bp
from backend.settings import DB_URI, SECRET_KEY


def create_app(config=None):
    app = Flask(__name__)

    # load default configuration
    app.config.from_object('backend.settings')

    # load environment configuration
    if 'WEBSITE_CONF' in os.environ:
        app.config.from_envvar('WEBSITE_CONF')

    # load app specified configuration
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith('.py'):
            app.config.from_pyfile(config)

    setup_app(app)
    return app


def setup_app(app):
    db.init_app(app)
    # Create tables if they do not exist already
    with app.app_context():
        db.create_all()
        if len(User.query.filter_by(isAdmin=True).all()) == 0:
            db.session.add(User(username="admin", email="admin@admin.com", name="Admin", surname="Admin", password=User.gen_password("admin"), isAdmin=True))
            db.session.commit()
    config_oauth(app)
    app.register_blueprint(bp, url_prefix='')


app = create_app({
    'SECRET_KEY': SECRET_KEY,
    'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': DB_URI,
})

app.run("0.0.0.0", 8000, True)
