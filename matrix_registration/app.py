import logging
import logging.config
import click

from flask import Flask
from flask.cli import FlaskGroup, pass_script_info
from flask_cors import CORS
from waitress import serve

from . import captcha
from .captcha import db
from . import config
import os


def create_app(testing=False):
    app = Flask(__name__)
    app.testing = testing

    with app.app_context():
        from .api import api
        app.register_blueprint(api)

    return app


@click.group(cls=FlaskGroup,
             add_default_commands=False,
             create_app=create_app,
             context_settings=dict(help_option_names=['-h', '--help']))
@click.option("--config-path",
              default="config.yaml",
              help='specifies the config file to be used')
@pass_script_info
def cli(info, config_path):
    """a token based matrix registration app"""
    config.config = config.Config(config_path)
    logging.config.dictConfig(config.config.logging)
    app = info.load_app()
    with app.app_context():
        app.config.from_mapping(
            SQLALCHEMY_DATABASE_URI=config.config.db.format(
                cwd=f"{os.getcwd()}/"),
            SQLALCHEMY_TRACK_MODIFICATIONS=False)
        db.init_app(app)
        db.create_all()
        captcha.captcha = captcha.CaptchaGenerator()


@cli.command("serve", help="start api server")
@pass_script_info
def run_server(info):
    app = info.load_app()
    if config.config.allow_cors:
        CORS(app)
    serve(app,
          host=config.config.host,
          port=config.config.port,
          url_prefix=config.config.base_url)


if __name__ == "__main__":
    cli()
    run_server()
