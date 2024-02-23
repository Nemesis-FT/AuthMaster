import os

import werkzeug
from flask import Flask, render_template
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
            db.session.add(User(username="admin", email="admin@admin.com", name="Admin", surname="Admin",
                                password=User.gen_password("admin"), isAdmin=True))
            db.session.commit()
    config_oauth(app)
    app.register_blueprint(bp, url_prefix='')


app = create_app({
    'SECRET_KEY': SECRET_KEY,
    'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': DB_URI,
})


@app.errorhandler(werkzeug.exceptions.NotFound)
def handle_not_found(e):
    return render_template("error_template.html", code=404,
                           message="The resource you're trying to access does not exist."), 404


@app.errorhandler(werkzeug.exceptions.Forbidden)
def handle_forbidden(e):
    return render_template("error_template.html", code=403,
                           message="You are not allowed to proceed."), 403


@app.errorhandler(werkzeug.exceptions.Unauthorized)
def handle_unauthorized(e):
    return render_template("error_template.html", code=401,
                           message="You entered the wrong credentials."), 401


@app.errorhandler(werkzeug.exceptions.InternalServerError)
def handle_forbidden(e):
    return render_template("error_template.html", code=500,
                           message="An unhandled error has occurred. Please notify administrators if this keeps happening."), 500


app.run("0.0.0.0", 8000)
