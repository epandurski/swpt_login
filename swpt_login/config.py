import json
from typing import Union
from os import environ


def _parse_dict(s: str) -> dict:
    try:
        return json.loads(s)
    except ValueError:
        raise ValueError(f"Invalid JSON configuration value: {s}")


def _str_or_nothing(s: str) -> Union[str, None]:
    return s or None


class MetaEnvReader(type):
    def __init__(cls, name, bases, dct):
        """MetaEnvReader class initializer.

        This function will get called when a new class which utilizes
        this metaclass is defined, as opposed to when an instance is
        initialized. This function overrides the default configuration
        from environment variables.

        """

        super().__init__(name, bases, dct)
        NoneType = type(None)
        annotations = dct.get("__annotations__", {})
        falsy_values = {"false", "off", "no", ""}
        for key, value in environ.items():
            if hasattr(cls, key):
                target_type = annotations.get(key) or type(getattr(cls, key))
                if target_type is NoneType:
                    target_type = str

                if target_type is bool:
                    value = value.lower() not in falsy_values
                else:
                    value = target_type(value)

                setattr(cls, key, value)


class Configuration(metaclass=MetaEnvReader):
    SQLALCHEMY_DATABASE_URI = ""
    SQLALCHEMY_ENGINE_OPTIONS: _parse_dict = _parse_dict('{"pool_size": 0}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False

    POSTGRES_CONNECTION_POOL_SIZE = 0
    POSTGRES_REPLICA_URL = ""

    REDIS_URL = "redis://localhost:6379/0"
    REDIS_CLUSTER_URL = ""

    MAIL_SERVER = "localhost"
    MAIL_PORT = 25
    MAIL_USE_TLS = False
    MAIL_USE_SSL = False
    MAIL_USERNAME: _str_or_nothing = None
    MAIL_PASSWORD: _str_or_nothing = None
    MAIL_DEFAULT_SENDER: str = None
    MAIL_MAX_EMAILS: int = None
    MAIL_ASCII_ATTACHMENTS = False

    CAPTCHA_SITEKEY = "10000000-ffff-ffff-ffff-000000000001"
    CAPTCHA_SITEKEY_SECRET = "0x0000000000000000000000000000000000000000"
    CAPTCHA_DIV_CLASS = "h-captcha"
    CAPTCHA_SCRIPT_TYPE = ""  # Alternatively, this can be "module".
    CAPTCHA_SCRIPT_SRC = "https://js.hcaptcha.com/1/api.js"
    CAPTCHA_SCRIPT_SRC_LANG_QUERY_PARAM = "hl"  # This can also be an empty sting.
    CAPTCHA_RESPONSE_FIELD_NAME = "h-captcha-response"
    CAPTCHA_VERIFY_URL = "https://api.hcaptcha.com/siteverify"
    CAPTCHA_VERIFY_AUTH_HEADER = ""  # Friendly Captcha uses "X-API-Key".
    CAPTCHA_VERIFY_SEND_REMOTE_IP = True
    CAPTCHA_VERIFY_TIMEOUT_SECONDS: float = 5.0

    ALTCHA_SECRET_HMAC_KEY = "dummy-secret"
    ALTCHA_MAX_NUMBER = 100000  # ALTCHA's computational complexity
    ALTCHA_INFO_URL = "https://altcha.org/"
    ALTCHA_AUTO_SOLVE = "onsubmit"  # alternatives: "off", "onfocus", "onload", "onsubmit"
    ALTCHA_EXPIRATION_SECONDS = 60 * 60
    ALTCHA_HIDELOGO = True
    ALTCHA_HIDEFOOTER = False

    ALLOW_SIGNUP = True
    SHOW_CAPTCHA_ON_SIGNUP = True
    SHOW_ALTCHA_ON_LOGIN = True
    SITE_TITLE = "Login Test Site"
    LANGUAGES = "en"  # separated by a comma, for example "en,bg", the first is default
    ABOUT_URL = "https://swaptacular.github.io/overview"
    STYLE_NAME = "default"
    STYLE_URL = ""
    SUSPENDED_ACCOUNT_HELP_URL = ""
    SIGNED_UP_REDIRECT_URL = ""  # It is highly recommended to set this!

    SUBJECT_PREFIX = ""  # Must be "debtors:" or "creditors:".

    HYDRA_ADMIN_URL = "http://hydra:4445/"
    HYDRA_REQUEST_TIMEOUT_SECONDS = 5
    SUPERUSER_CLIENT_ID = "users-superuser"
    SUPERUSER_CLIENT_SECRET = "users-superuser"
    API_AUTH2_TOKEN_URL = "https://hydra/oauth2/token"
    API_RESOURCE_SERVER = "https://resource-server"
    API_TIMEOUT_SECONDS = 5

    FLUSH_PROCESSES = 1
    FLUSH_PERIOD = 2.0

    # Limit Flask content lengths.
    MAX_CONTENT_LENGTH = 16384
    MAX_FORM_MEMORY_SIZE = 16384
    MAX_FORM_PARTS = 10

    # Other settings:
    #
    VERSION = "1.1.0"
    LOGIN_PATH = "/login"
    CONSENT_PATH = "/consent"
    SECRET_KEY = "dummy-secret"
    SIGNUP_IP_BLOCK_SECONDS = 60 * 60
    SIGNUP_IP_MAX_EMAILS = 50
    LOGIN_HISTORY_EXPIRATION_DAYS = 180
    LOGIN_VERIFIED_DEVICES_MAX_COUNT = 10
    LOGIN_VERIFICATION_CODE_EXPIRATION_SECONDS = 60 * 60
    MAX_LOGINS_PER_MONTH = 10000
    SECRET_CODE_MAX_ATTEMPTS = 10
    SIGNUP_REQUEST_EXPIRATION_SECONDS = 24 * 60 * 60
    CHANGE_EMAIL_REQUEST_EXPIRATION_SECONDS = 24 * 60 * 60
    CHANGE_RECOVERY_CODE_REQUEST_EXPIRATION_SECONDS = 60 * 60
    LANGUAGE_COOKIE_NAME = "user_lang"
    COMPUTER_CODE_COOKIE_NAME = "user_cc"
    LOGIN_VERIFICATION_COOKIE_NAME = "user_lv"
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_MAX_LENGTH = 64
    SEND_FILE_MAX_AGE_DEFAULT = 12096000  # max-age for static files
    BABEL_DEFAULT_LOCALE = "en"
    BABEL_DEFAULT_TIMEZONE = "UTC"
    APP_FLUSH_ACTIVATE_USERS_BURST_COUNT = 5
    APP_FLUSH_DEACTIVATE_USERS_BURST_COUNT = 5

    # NOTE: We may make SSL requests to the debtors/creditors Web API.
    # However, those requests will be to an internal hostname, not to
    # the canonical hostname. Therefore, normally we would not be able
    # to verify the SSL certificate.
    APP_VERIFY_SSL_CERTIFICATES = False
