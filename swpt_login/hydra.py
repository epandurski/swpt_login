import logging
from urllib.parse import urljoin, quote_plus
from flask import current_app
from .redis import increment_key_with_limit, UserLoginsHistory, ExceededValueLimitError
from .extensions import requests_session


def get_subject(user_id):
    return current_app.config["SUBJECT_PREFIX"] + str(user_id)


def invalidate_credentials(user_id):
    UserLoginsHistory(user_id).clear()
    subject = quote_plus(get_subject(user_id))
    revoke_consent_sessions(subject)
    invalidate_login_sessions(subject)


def revoke_consent_sessions(subject):
    timeout = float(current_app.config["HYDRA_REQUEST_TIMEOUT_SECONDS"])
    hydra_consents_base_url = urljoin(
        current_app.config["HYDRA_ADMIN_URL"], "oauth2/auth/sessions/consent"
    )
    r = requests_session.delete(
        f"{hydra_consents_base_url}?subject={subject}&all=true", timeout=timeout
    )
    r.raise_for_status()


def invalidate_login_sessions(subject):
    timeout = float(current_app.config["HYDRA_REQUEST_TIMEOUT_SECONDS"])
    hydra_logins_base_url = urljoin(
        current_app.config["HYDRA_ADMIN_URL"], "oauth2/auth/sessions/login"
    )
    r = requests_session.delete(
        f"{hydra_logins_base_url}?subject={subject}", timeout=timeout
    )
    r.raise_for_status()


class LoginRequest:
    LOGIN_COUNT_SUBJECT_PREFIX = "logins:"

    class TooManyLogins(Exception):
        """Too many login attempts."""

    def __init__(self, challenge_id):
        self.challenge_id = challenge_id
        self.timeout = float(current_app.config["HYDRA_REQUEST_TIMEOUT_SECONDS"])
        base_url = urljoin(
            current_app.config["HYDRA_ADMIN_URL"], "oauth2/auth/requests/"
        )
        self.fetch_url = urljoin(base_url, "login")
        self.accept_url = urljoin(base_url, "login/accept")
        self.reject_url = urljoin(base_url, "login/reject")

    def register_successful_login(self, subject):
        key = self.LOGIN_COUNT_SUBJECT_PREFIX + subject
        try:
            increment_key_with_limit(
                key,
                limit=current_app.config["MAX_LOGINS_PER_MONTH"],
                period_seconds=2600000,
            )
        except ExceededValueLimitError:
            raise self.TooManyLogins()

    def fetch(self):
        """Return the subject and the preferred language.

        If not already logged the subject will be `None`.
        """

        r = requests_session.get(
            url=self.fetch_url,
            params={"login_challenge": self.challenge_id},
            timeout=self.timeout,
        )
        r.raise_for_status()
        fetched_data = r.json()
        client_metadata = fetched_data["client"].get("metadata")
        return (
            fetched_data["subject"] if fetched_data["skip"] else None,
            client_metadata.get("language") if client_metadata else None,
        )

    def accept(self, subject, remember=False, remember_for=1000000000):
        """Accept the request unless the limit is reached, return an URL to redirect to."""

        try:
            self.register_successful_login(subject)
        except self.TooManyLogins:
            return self.reject()

        r = requests_session.put(
            url=self.accept_url,
            params={"login_challenge": self.challenge_id},
            timeout=self.timeout,
            json={
                "subject": subject,
                "remember": remember,
                "remember_for": remember_for,
            },
        )
        r.raise_for_status()
        logger = logging.getLogger(__name__)
        logger.debug("Successful login", extra={"subject": subject})
        return r.json()["redirect_to"]

    def reject(self):
        """Reject the request, return an URL to redirect to."""

        r = requests_session.put(
            url=self.reject_url,
            params={"login_challenge": self.challenge_id},
            timeout=self.timeout,
            json={
                "error": "too_many_logins",
                "error_description": (
                    "Too many login attempts have been made in a given period of time."
                ),
            },
        )
        r.raise_for_status()
        return r.json()["redirect_to"]


class ConsentRequest:
    def __init__(self, challenge_id):
        self.challenge_id = challenge_id
        self.timeout = float(current_app.config["HYDRA_REQUEST_TIMEOUT_SECONDS"])
        base_url = urljoin(
            current_app.config["HYDRA_ADMIN_URL"], "oauth2/auth/requests/"
        )
        self.fetch_url = urljoin(base_url, "consent")
        self.accept_url = urljoin(base_url, "consent/accept")

    def fetch(self):
        """Return the consentRequest dict, or `None` if no consent is required."""

        r = requests_session.get(
            url=self.fetch_url,
            params={"consent_challenge": self.challenge_id},
            timeout=self.timeout,
        )
        r.raise_for_status()
        fetched_data = r.json()
        return None if fetched_data["skip"] else fetched_data

    def accept(self, grant_scope, remember=False, remember_for=0):
        """Approve the request, return an URL to redirect to."""

        r = requests_session.put(
            url=self.accept_url,
            params={"consent_challenge": self.challenge_id},
            timeout=self.timeout,
            json={
                "grant_scope": grant_scope,
                "remember": remember,
                "remember_for": remember_for,
            },
        )
        r.raise_for_status()
        return r.json()["redirect_to"]
