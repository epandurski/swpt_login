import pytest
import re
from typing import Callable
from dataclasses import dataclass
from unittest.mock import Mock
from swpt_login import redis
from swpt_login import utils
from swpt_login import models as m
from swpt_login.extensions import mail


def get_cookie(response, name):
    """Checks for a cookie and return its value, or None."""
    from werkzeug.http import parse_cookie

    cookies = response.headers.getlist("Set-Cookie")
    for cookie in cookies:
        c_key, c_value = next(parse_cookie(cookie).items())
        if c_key == name:
            return c_value

    assert None


@dataclass
class Response:
    status_code: int
    json: Callable = lambda: {}
    raise_for_status = Mock()


@pytest.fixture(scope="function")
def client(app, db_session):
    return app.test_client()


USER_ID = "1234"
USER_EMAIL = "test@example.com"
USER_SALT = utils.generate_password_salt()
USER_PASSWORD = "qwertyuiopasdfg"
USER_RECOVERY_CODE = utils.generate_recovery_code()


@pytest.fixture(params=[200, 409, 422, 500])
def acitivation_status_code(request):
    return request.param


@pytest.fixture
def user(db_session):
    redis._clear_user_verification_code_failures(USER_ID)
    db_session.add(
        m.UserRegistration(
            user_id=USER_ID,
            email=USER_EMAIL,
            salt=USER_SALT,
            password_hash=utils.calc_crypt_hash(USER_SALT, USER_PASSWORD),
            recovery_code_hash=utils.calc_crypt_hash("", USER_RECOVERY_CODE),
        )
    )
    db_session.commit()


def test_404_error(client):
    r = client.get("/login/invalid-path")
    assert r.status_code == 404


def test_set_language(client):
    r = client.get("/login/language/en?to=http://localhost/login/signup")
    assert r.status_code == 302
    assert r.location == "http://localhost/login/signup"
    assert get_cookie(r, "user_lang") == "en"


def test_stylesheet(client):
    r = client.get("/login/signup")
    assert r.status_code == 200
    assert "style-default.css" in r.get_data(as_text=True)


def test_signup(mocker, client, db_session, acitivation_status_code):
    class ReservationMock:
        post = Mock(
            return_value=Response(
                200,
                lambda: {
                    "type": "DebtorReservation",
                    "createdAt": "2019-08-24T14:15:22Z",
                    "debtorId": "1234",
                    "reservationId": "456",
                    "validUntil": "2099-08-24T14:15:22Z",
                },
            )
        )

    class ActivationMock:
        post = Mock(
            return_value=Response(
                acitivation_status_code,
                lambda: {
                    "type": "Debtor",
                    "uri": "/debtors/1234/",
                    # The real response has more fields, but they will be
                    # ignored.
                },
            )
        )

    mocker.patch("swpt_login.redis.requests_session", ReservationMock())
    mocker.patch("swpt_login.models.requests_session", ActivationMock())

    r = client.get("/login/signup")
    assert r.status_code == 200
    assert "Create a New Account" in r.get_data(as_text=True)

    with mail.record_messages() as outbox:
        r = client.post(
            "/login/signup",
            data={
                "email": USER_EMAIL,
            },
        )
        assert r.status_code == 302
        r = client.get(r.location)
        assert "Please check your inbox" in r.get_data(as_text=True)
        assert len(outbox) == 1
        assert outbox[0].subject == "Create a New Account"
        msg = str(outbox[0])

    match = re.search(r"^http://localhost(/login/password/[^/\s]+)", msg, flags=re.M)
    assert match
    received_link = match[1]
    r = client.get(received_link)
    assert r.status_code == 200
    assert "Choose Password" in r.get_data(as_text=True)

    r = client.post(
        received_link,
        data={
            "password": USER_PASSWORD,
            "confirm": USER_PASSWORD,
        },
    )
    assert r.status_code == 200
    assert "Your account recovery code is" in r.get_data(as_text=True)

    if acitivation_status_code == 200:
        user = m.UserRegistration.query.one_or_none()
        assert user
        assert user.user_id == "1234"
        assert user.email == USER_EMAIL
        assert user.password_hash == utils.calc_crypt_hash(user.salt, USER_PASSWORD)
        assert str(user.registered_from_ip) == "127.0.0.1"
        assert len(m.ActivateUserSignal.query.all()) == 0
    elif acitivation_status_code in [409, 422]:
        assert len(m.UserRegistration.query.all()) == 0
        assert len(m.ActivateUserSignal.query.all()) == 0
    else:
        assert len(m.UserRegistration.query.all()) == 0
        assert len(m.ActivateUserSignal.query.all()) == 1


def test_change_password(mocker, client, db_session, user):
    invalidate_credentials = Mock()
    mocker.patch("swpt_login.hydra.invalidate_credentials", invalidate_credentials)

    r = client.get("/login/signup?recover=true")
    assert r.status_code == 200
    assert "Change Account Password" in r.get_data(as_text=True)

    with mail.record_messages() as outbox:
        r = client.post(
            "/login/signup?recover=true",
            data={
                "email": USER_EMAIL,
            },
        )
        assert r.status_code == 302
        r = client.get(r.location)
        assert "Please check your inbox" in r.get_data(as_text=True)
        assert len(outbox) == 1
        assert outbox[0].subject == "Change Account Password"
        msg = str(outbox[0])

    match = re.search(r"^http://localhost(/login/password/[^/\s]+)", msg, flags=re.M)
    assert match
    received_link = match[1]
    r = client.get(received_link)
    assert r.status_code == 200
    assert "Choose Password" in r.get_data(as_text=True)

    r = client.post(
        received_link,
        data={
            "recovery_code": "wrong_recovery_code",
            "password": "my shiny new password",
            "confirm": "my shiny new password",
        },
    )
    assert r.status_code == 200
    assert "Incorrect recovery code" in r.get_data(as_text=True)
    invalidate_credentials.assert_not_called()
    assert m.UserRegistration.query.filter_by(
        password_hash=utils.calc_crypt_hash(USER_SALT, USER_PASSWORD),
    ).one_or_none()

    r = client.post(
        received_link,
        data={
            "recovery_code": USER_RECOVERY_CODE,
            "password": "my shiny new password",
            "confirm": "my shiny new password",
        },
    )
    assert r.status_code == 200
    invalidate_credentials.assert_called_with(USER_ID)
    assert "Your password has been successfully reset" in r.get_data(as_text=True)
    assert m.UserRegistration.query.filter_by(
        password_hash=utils.calc_crypt_hash(USER_SALT, "my shiny new password"),
    ).one_or_none()


def test_change_recovery_code(client, db_session, user):
    r = client.get("/login/change-recovery-code?login_challenge=9876")
    assert r.status_code == 200
    assert "Change Recovery Code" in r.get_data(as_text=True)
    assert "Enter your email" in r.get_data(as_text=True)

    with mail.record_messages() as outbox:
        r = client.post(
            "/login/change-recovery-code",
            data={
                "email": USER_EMAIL,
            },
        )
        assert r.status_code == 302
        r = client.get(r.location)
        assert "An email has been sent" in r.get_data(as_text=True)
        assert len(outbox) == 1
        assert outbox[0].subject == "Change Recovery Code"
        msg = str(outbox[0])

    match = re.search(
        r"^http://localhost(/login/recovery-code/[^/\s]+)", msg, flags=re.M
    )
    assert match
    received_link = match[1]
    r = client.get(received_link)
    assert r.status_code == 200
    assert "Change Recovery Code" in r.get_data(as_text=True)
    assert "Enter your password" in r.get_data(as_text=True)

    r = client.post(
        received_link,
        data={
            "password": "wrong_password",
        },
    )
    assert r.status_code == 200
    assert "Incorrect password" in r.get_data(as_text=True)
    assert m.UserRegistration.query.filter_by(
        recovery_code_hash=utils.calc_crypt_hash("", USER_RECOVERY_CODE),
    ).one_or_none()

    r = client.post(
        received_link,
        data={
            "password": USER_PASSWORD,
        },
    )
    assert r.status_code == 200
    assert "Your account recovery code has been changed" in r.get_data(as_text=True)
    assert not m.UserRegistration.query.filter_by(
        recovery_code_hash=utils.calc_crypt_hash("", USER_RECOVERY_CODE),
    ).one_or_none()


def test_change_email(mocker, client, db_session, user):
    invalidate_credentials = Mock()
    mocker.patch("swpt_login.hydra.invalidate_credentials", invalidate_credentials)

    r = client.get("/login/change-email?login_challenge=9876")
    assert r.status_code == 200
    assert "Change Email Address" in r.get_data(as_text=True)
    assert "Enter your old email" in r.get_data(as_text=True)
    assert "Enter your password" in r.get_data(as_text=True)

    r = client.post(
        "/login/change-email?login_challenge=9876",
        data={
            "email": USER_EMAIL,
            "password": "wrong_password",
        },
    )
    assert r.status_code == 200
    assert "Change Email Address" in r.get_data(as_text=True)
    assert "Enter your old email" in r.get_data(as_text=True)
    assert "Enter your password" in r.get_data(as_text=True)
    assert "Incorrect email or password" in r.get_data(as_text=True)

    with mail.record_messages() as outbox:
        r = client.post(
            "/login/change-email?login_challenge=9876",
            data={
                "email": USER_EMAIL,
                "password": USER_PASSWORD,
            },
        )
        assert r.status_code == 302
        assert len(outbox) == 1
        assert outbox[0].subject == "Change Email Address"
        assert USER_EMAIL in outbox[0].recipients
        redirect_location = r.location

    r = client.get(redirect_location)
    assert r.status_code == 200
    assert "Change Email Address" in r.get_data(as_text=True)
    assert "Enter your recovery code" in r.get_data(as_text=True)
    assert "Enter your new email" in r.get_data(as_text=True)

    r = client.post(
        redirect_location,
        data={
            "recovery_code": "wrong_recovery_code",
            "email": "new-email@example.com",
        },
    )
    assert r.status_code == 200
    assert "Change Email Address" in r.get_data(as_text=True)
    assert "Incorrect recovery code" in r.get_data(as_text=True)

    with mail.record_messages() as outbox:
        r = client.post(
            redirect_location,
            data={
                "recovery_code": USER_RECOVERY_CODE,
                "email": "new-email@example.com",
            },
        )
        assert r.status_code == 302
        second_redirect_location = r.location

        r = client.get(second_redirect_location)
        assert r.status_code == 200
        assert "An email has been sent to" in r.get_data(as_text=True)

        assert len(outbox) == 1
        assert outbox[0].subject == "Change Email Address"
        assert "new-email@example.com" in outbox[0].recipients
        msg = str(outbox[0])

    match = re.search(
        r"^http://localhost(/login/change-email/[^/\s]+)", msg, flags=re.M
    )
    assert match
    received_link = match[1]
    r = client.get(received_link)
    assert r.status_code == 200
    assert "Change Email Address" in r.get_data(as_text=True)
    assert "Enter your password" in r.get_data(as_text=True)
    invalidate_credentials.assert_not_called()

    # The password must be entered once again in case the last email
    # has been read by someone else, who have followed the link.
    r = client.post(
        received_link,
        data={
            "password": "wrong_password",
        },
    )
    assert r.status_code == 200
    assert "Incorrect password" in r.get_data(as_text=True)

    r = client.post(
        received_link,
        data={
            "password": USER_PASSWORD,
        },
    )
    assert r.status_code == 302
    third_redirect_location = r.location

    r = client.get(third_redirect_location)
    assert r.status_code == 200
    assert (
        "The email address on your account has been successfully changed"
        in r.get_data(as_text=True)
    )

    invalidate_credentials.assert_called_with(USER_ID)
    assert not m.UserRegistration.query.filter_by(email=USER_EMAIL).one_or_none()
    assert m.UserRegistration.query.filter_by(
        email="new-email@example.com"
    ).one_or_none()


def test_change_email_failure(mocker, client, db_session, user):
    invalidate_credentials = Mock()
    mocker.patch("swpt_login.hydra.invalidate_credentials", invalidate_credentials)

    # An user with the desired new email already exists!
    db_session.add(
        m.UserRegistration(
            user_id="1",
            email="new-email@example.com",
            salt="abcd",
            password_hash="1234",
            recovery_code_hash="7890",
        )
    )
    db_session.commit()

    r = client.post(
        "/login/change-email?login_challenge=9876",
        data={
            "email": USER_EMAIL,
            "password": USER_PASSWORD,
        },
    )
    redirect_location = r.location

    with mail.record_messages() as outbox:
        r = client.post(
            redirect_location,
            data={
                "recovery_code": USER_RECOVERY_CODE,
                "email": "new-email@example.com",
            },
        )
        msg = str(outbox[0])

    match = re.search(
        r"^http://localhost(/login/change-email/[^/\s]+)", msg, flags=re.M
    )
    received_link = match[1]
    r = client.get(received_link)
    # invalidate_credentials.assert_not_called()

    r = client.post(
        received_link,
        data={
            "password": USER_PASSWORD,
        },
    )
    third_redirect_location = r.location

    r = client.get(third_redirect_location)
    assert r.status_code == 200
    assert "The email address on your account can not be changed to" in r.get_data(
        as_text=True
    )

    invalidate_credentials.assert_not_called()
    assert m.UserRegistration.query.filter_by(
        user_id=USER_ID,
        email=USER_EMAIL,
    ).one_or_none()
    assert m.UserRegistration.query.filter_by(
        user_id="1",
        email="new-email@example.com",
    ).one_or_none()


def test_login_flow(mocker, client, app, db_session, user):
    @dataclass
    class LoginRequestMock:
        fetch = Mock(return_value=None)
        accept = Mock(return_value="http://example.com/after-login/")
        challenge_id = "9876"

    mocker.patch(
        "swpt_login.hydra.LoginRequest",
        Mock(return_value=LoginRequestMock()),
    )

    r = client.get("/login/?login_challenge=9876")
    assert r.status_code == 200
    assert "Enter your email" in r.get_data(as_text=True)
    assert "Enter your password" in r.get_data(as_text=True)

    r = client.post(
        "/login/?login_challenge=9876",
        data={
            "email": USER_EMAIL,
            "password": "wrong_password",
        },
    )
    assert r.status_code == 200
    assert "Enter your email" in r.get_data(as_text=True)
    assert "Enter your password" in r.get_data(as_text=True)
    assert "Incorrect email or password" in r.get_data(as_text=True)

    with mail.record_messages() as outbox:
        r = client.post(
            "/login/?login_challenge=9876",
            data={
                "email": USER_EMAIL,
                "password": USER_PASSWORD,
            },
        )
        assert r.status_code == 302
        redirect_location = r.location
        assert get_cookie(r, "user_cc") is not None
        assert get_cookie(r, "user_lv") is not None

        # TODO: pass the cookie here?
        r = client.get(redirect_location)
        assert r.status_code == 200
        assert "An email has been sent to" in r.get_data(as_text=True)
        assert "Enter the verification code" in r.get_data(as_text=True)

        assert len(outbox) == 1
        assert outbox[0].subject.startswith("New login from")
        assert USER_EMAIL in outbox[0].recipients
        msg = str(outbox[0])

    match = re.search(r"^The login verification code is: (\d+)", msg, flags=re.M)
    assert match
    verivication_code = match[1]

    r = client.post(
        redirect_location,
        data={
            "verification_code": "wrong_verivication_code",
        },
    )
    assert r.status_code == 200
    assert "Enter the verification code" in r.get_data(as_text=True)
    assert "Invalid verification code" in r.get_data(as_text=True)

    r = client.post(
        redirect_location,
        data={
            "verification_code": verivication_code,
        },
    )
    assert r.status_code == 302
    assert r.location == "http://example.com/after-login/"


def test_delete_account(client, db_session, user):
    r = client.get("/login/delete-account?login_challenge=9876")
    assert r.status_code == 200
    assert "Delete Your Account" in r.get_data(as_text=True)
    assert "Enter your email" in r.get_data(as_text=True)
    assert "Enter your password" in r.get_data(as_text=True)

    r = client.post(
        "/login/delete-account?login_challenge=9876",
        data={
            "email": USER_EMAIL,
            "password": "wrong_password",
        },
    )
    assert r.status_code == 200
    assert "Delete Your Account" in r.get_data(as_text=True)
    assert "Enter your email" in r.get_data(as_text=True)
    assert "Enter your password" in r.get_data(as_text=True)
    assert "Incorrect email or password" in r.get_data(as_text=True)

    with mail.record_messages() as outbox:
        r = client.post(
            "/login/delete-account?login_challenge=9876",
            data={
                "email": USER_EMAIL,
                "password": USER_PASSWORD,
            },
        )
        assert r.status_code == 302
        assert len(outbox) == 1
        assert outbox[0].subject == "Delete Account"
        assert USER_EMAIL in outbox[0].recipients

        r = client.get(r.location)
        assert r.status_code == 200
        assert "An email has been sent to" in r.get_data(as_text=True)
        msg = str(outbox[0])

    match = re.search(
        r"^http://localhost(/login/confirm-deletion/[^/\s]+)", msg, flags=re.M
    )
    assert match
    received_link = match[1]
    r = client.get(received_link)
    assert r.status_code == 200
    assert "Enter your password" in r.get_data(as_text=True)

    # The password must be entered once again in case the last email
    # has been read by someone else, who have followed the link.
    r = client.post(
        received_link,
        data={
            "confirmed_deletion": "yes",
            "password": "wrong_password",
        },
    )
    assert r.status_code == 200
    assert "Incorrect password" in r.get_data(as_text=True)
    assert len(m.UserRegistration.query.all()) == 1
    assert len(m.DeactivateUserSignal.query.all()) == 0

    r = client.post(
        received_link,
        data={
            "confirmed_deletion": "yes",
            "password": USER_PASSWORD,
        },
    )
    assert r.status_code == 302
    redirect_location = r.location

    r = client.get(redirect_location)
    assert r.status_code == 200
    assert "has been deleted" in r.get_data(as_text=True)

    assert not m.UserRegistration.query.filter_by(email=USER_EMAIL).one_or_none()
    signals = m.DeactivateUserSignal.query.filter_by().all()
    assert len(signals) == 1
    assert signals[0].user_id == USER_ID


def test_login_inactive_account(mocker, client, app, db_session):
    @dataclass
    class LoginRequestMock:
        fetch = Mock(return_value=None)
        accept = Mock(return_value="http://example.com/after-login/")
        challenge_id = "9876"

    mocker.patch(
        "swpt_login.hydra.LoginRequest",
        Mock(return_value=LoginRequestMock()),
    )
    db_session.add(
        m.UserRegistration(
            user_id=USER_ID,
            email=USER_EMAIL,
            salt=USER_SALT,
            password_hash=utils.calc_crypt_hash(USER_SALT, USER_PASSWORD),
            recovery_code_hash=utils.calc_crypt_hash("", USER_RECOVERY_CODE),
            status=1,  # inacitve
        )
    )
    db_session.commit()

    r = client.get("/login/?login_challenge=9876")
    assert r.status_code == 200
    assert "Enter your email" in r.get_data(as_text=True)
    assert "Enter your password" in r.get_data(as_text=True)

    r = client.post(
        "/login/?login_challenge=9876",
        data={
            "email": USER_EMAIL,
            "password": USER_PASSWORD,
        },
    )
    assert r.status_code == 200
    assert "Your account has been suspended" in r.get_data(as_text=True)


def test_healthz(client, app):
    r = client.get("/login/healthz")
    assert r.status_code == 200
