import logging
import sys
import signal
import os
import os.path
import socket
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from typing import List
from flask import render_template


def _raise_keyboard_interrupt(signum, frame):  # pragma: no cover
    logger = logging.getLogger(__name__)
    logger.warning("Received %s signal. Exiting...", signal.strsignal(signum))
    raise KeyboardInterrupt()


def _excepthook(exc_type, exc_value, traceback):
    logging.error(
        "Uncaught exception occured", exc_info=(exc_type, exc_value, traceback)
    )


def _remove_handlers(logger):
    for h in logger.handlers:
        logger.removeHandler(h)


def _add_console_hander(logger, format: str):
    handler = logging.StreamHandler(sys.stdout)
    fmt = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"

    if format == "text":
        handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S%z"))
    elif format == "json":
        from pythonjsonlogger import jsonlogger

        handler.setFormatter(
            jsonlogger.JsonFormatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S%z")
        )
    else:
        raise RuntimeError(f"invalid log format: {format}")

    logger.addHandler(handler)


def _configure_root_logger(format: str) -> logging.Logger:
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)
    _remove_handlers(root_logger)
    _add_console_hander(root_logger, format)

    return root_logger


def _server_error(error=None):
    return render_template("500.html")


def _get_language_choices(languages):
    supported_languages = {"en": "English", "bg": "Български"}
    languages = [lg.strip() for lg in languages.split(",")]
    language_choices = [
        (lg, supported_languages[lg])
        for lg in languages
        if lg in supported_languages
    ]
    if not language_choices:
        raise ValueError("The LANGUAGES envvar contains no supported languages.")

    return language_choices


def configure_logging(level: str, format: str, associated_loggers: List[str]) -> None:
    root_logger = _configure_root_logger(format)

    # Set the log level for this app's logger.
    app_logger = logging.getLogger(__name__)
    app_logger.setLevel(level.upper())
    app_logger_level = app_logger.getEffectiveLevel()

    # Make sure that all loggers that are associated to this app have
    # their log levels set to the specified level as well.
    for qualname in associated_loggers:
        logging.getLogger(qualname).setLevel(app_logger_level)

    # Make sure that the root logger's log level (that is: the log
    # level for all third party libraires) is not lower than the
    # specified level.
    if app_logger_level > root_logger.getEffectiveLevel():
        root_logger.setLevel(app_logger_level)

    # Delete all gunicorn's log handlers (they are not needed in a
    # docker container because everything goes to the stdout anyway),
    # and make sure that the gunicorn logger's log level is not lower
    # than the specified level.
    gunicorn_logger = logging.getLogger("gunicorn.error")
    gunicorn_logger.propagate = True
    _remove_handlers(gunicorn_logger)
    if app_logger_level > gunicorn_logger.getEffectiveLevel():
        gunicorn_logger.setLevel(app_logger_level)


def create_app(config_dict={}):
    from werkzeug.middleware.proxy_fix import ProxyFix
    from flask import Flask
    from . import extensions
    from .config import Configuration
    from .routes import login, consent
    from .cli import swpt_login

    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_port=1)
    app.config.from_object(Configuration)
    app.config.from_mapping(config_dict)

    if not app.config["TESTING"]:
        socket.setdefaulttimeout(5.0)

    app.config["LANGUAGE_CHOICES"] = _get_language_choices(app.config["LANGUAGES"])

    engine_options = app.config["SQLALCHEMY_ENGINE_OPTIONS"]
    engine_options["pool_size"] = app.config["POSTGRES_CONNECTION_POOL_SIZE"]
    app.config["SQLALCHEMY_BINDS"] = {
        "replica": {
            "url": (
                app.config["POSTGRES_REPLICA_URL"]
                or app.config["SQLALCHEMY_DATABASE_URI"]
            ),
            **engine_options,
        },
    }

    subject_prefix = app.config["SUBJECT_PREFIX"]
    if subject_prefix == "debtors:":
        app.config["API_RESERVE_USER_ID_PATH"] = "/debtors/.debtor-reserve"
        app.config["API_USER_ID_FIELD_NAME"] = "debtorId"
        app.config["API_DACTIVATION_REQUEST_TYPE"] = "DebtorDeactivationRequest"
    elif subject_prefix == "creditors:":
        app.config["API_RESERVE_USER_ID_PATH"] = "/creditors/.creditor-reserve"
        app.config["API_USER_ID_FIELD_NAME"] = "creditorId"
        app.config["API_DACTIVATION_REQUEST_TYPE"] = "CreditorDeactivationRequest"
    else:
        raise RuntimeError("invalid SUBJECT_PREFIX")

    extensions.init_app(app)
    app.register_blueprint(login, url_prefix=app.config["LOGIN_PATH"])
    app.register_blueprint(consent, url_prefix=app.config["CONSENT_PATH"])
    app.register_error_handler(500, _server_error)
    app.register_error_handler(403, _server_error)
    app.cli.add_command(swpt_login)
    return app


configure_logging(
    level=os.environ.get("APP_LOG_LEVEL", "warning"),
    format=os.environ.get("APP_LOG_FORMAT", "text"),
    associated_loggers=os.environ.get("APP_ASSOCIATED_LOGGERS", "").split(),
)
sys.excepthook = _excepthook
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

if signal.getsignal(signal.SIGTERM) in [signal.SIG_IGN, signal.SIG_DFL, None]:
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
