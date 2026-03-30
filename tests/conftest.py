import pytest
import sqlalchemy
import flask_migrate
from datetime import datetime, timezone
from swpt_login import create_app
from swpt_login.extensions import db

config_dict = {
    "TESTING": True,
    "PREFERRED_URL_SCHEME": "http",
    "LOGIN_PATH": "/login",
    "CONSENT_PATH": "/consent",
    "SUBJECT_PREFIX": "debtors:",
    "API_RESOURCE_SERVER": "https://resource-server.example.com",
    "SECRET_CODE_MAX_ATTEMPTS": 5,
    "MAIL_SUPPRESS_SEND": False,
    "MAIL_DEFAULT_SENDER": "Swaptacular <no-reply@example.com>",
    "LOGIN_VERIFIED_DEVICES_MAX_COUNT": 3,
    "SHOW_CAPTCHA_ON_SIGNUP": False,
    "SIGNUP_IP_BLOCK_SECONDS": 1,
    "SIGNUP_IP_MAX_EMAILS": 100000000,
    "APP_VERIFY_SSL_CERTIFICATES": False,
    "SHOW_ALTCHA_ON_LOGIN": False,
    "STYLE_NAME": "default",
    "LANGUAGES": "en",
}


@pytest.fixture(scope="module")
def app(request):
    """Get a Flask application object."""

    app = create_app(config_dict)
    with app.app_context():
        flask_migrate.upgrade()
        yield app


@pytest.fixture(scope="function")
def db_session(app):
    """Get a Flask-SQLAlchmey session, with an automatic cleanup."""

    yield db.session

    # Cleanup:
    db.session.remove()
    for cmd in [
        "TRUNCATE TABLE user_registration",
        "TRUNCATE TABLE activate_user_signal",
        "TRUNCATE TABLE deactivate_user_signal",
    ]:
        db.session.execute(sqlalchemy.text(cmd))
    db.session.commit()


@pytest.fixture(scope="function")
def current_ts():
    return datetime.now(tz=timezone.utc)
