#!/bin/sh
set -e

# During development and testing, we should be able to connect to
# services installed on "localhost" from the container. To allow this,
# we find the IP address of the docker host, and then for each
# variable name in "$SUBSTITUTE_LOCALHOST_IN_VARS", we substitute
# "localhost" with that IP address.
host_ip=$(ip route show | awk '/default/ {print $3}')
for envvar_name in $SUBSTITUTE_LOCALHOST_IN_VARS; do
    eval envvar_value=\$$envvar_name
    if [[ -n "$envvar_value" ]]; then
        eval export $envvar_name=$(echo "$envvar_value" | sed -E "s/(.*@|.*\/\/)localhost\b/\1$host_ip/")
    fi
done

# The WEBSERVER_* variables should be used instead of the GUNICORN_*
# variables, because we do not want to tie the public interface to the
# "gunicorn" server, which we may, or may not use in the future.
export GUNICORN_WORKERS=${WEBSERVER_PROCESSES:-1}
export GUNICORN_THREADS=${WEBSERVER_THREADS:-3}

# The POSTGRES_URL variable should be used instead of the
# SQLALCHEMY_DATABASE_URI variable, because we do not want to tie the
# public interface to the "sqlalchemy" library, which we may, or may
# not use in the future.
export SQLALCHEMY_DATABASE_URI=${POSTGRES_URL}

# When SUBJECT_PREFIX is set to one of the two standard values (which
# must always be case), even if LOGIN_PATH and CONSENT_PATH variables
# are not set, we can guess their values with confidence.
case "$SUBJECT_PREFIX" in
    debtors:)
        export LOGIN_PATH=${LOGIN_PATH:-/debtors-login}
        export CONSENT_PATH=${CONSENT_PATH:-/debtors-consent}
        ;;
    creditors:)
        export LOGIN_PATH=${LOGIN_PATH:-/creditors-login}
        export CONSENT_PATH=${CONSENT_PATH:-/creditors-consent}
        ;;
    *)
        export SUBJECT_PREFIX=
        ;;
esac

# This function tries to upgrade the login database schema with
# exponential backoff. This is necessary during development, because
# the database might not be running yet when this script executes.
perform_db_upgrade() {
    local retry_after=1
    local time_limit=$(($retry_after << 5))
    local error_file="$APP_ROOT_DIR/flask-db-upgrade.error"
    echo -n 'Running login database schema upgrade ...'
    while [[ $retry_after -lt $time_limit ]]; do
        if flask db upgrade &>$error_file; then
            perform_db_initialization
            echo ' done.'
            return 0
        fi
        sleep $retry_after
        retry_after=$((2 * retry_after))
    done
    echo
    cat "$error_file"
    return 1
}

# This function is intended to perform additional one-time database
# initialization. Make sure that it is idempotent.
# (https://en.wikipedia.org/wiki/Idempotence)
perform_db_initialization() {
    return 0
}

case $1 in
    develop-run-flask)
        shift;
        exec flask run --host=0.0.0.0 --port $WEBSERVER_PORT --without-threads "$@"
        ;;
    test)
        # Do not run this in production!
        perform_db_upgrade
        exec pytest
        ;;
    configure)
        perform_db_upgrade
        ;;
    webserver)
        if [[ -z "$SUBJECT_PREFIX" ]]; then
            echo "Invalid SUBJECT_PREFIX."
            exit 1
        fi
        exec gunicorn --config "$APP_ROOT_DIR/gunicorn.conf.py" -b :$WEBSERVER_PORT wsgi:app
        ;;
    flush_activate_users  | flush_deactivate_users | flush_all)
        flush_activate_users=ActivateUserSignal
        flush_deactivate_users=DeactivateUserSignal
        flush_all=

        # For example: if `$1` is "flush_activate_users",
        # `signal_name` will be "ActivateUserSignal".
        eval signal_name=\$$1

        shift
        exec flask swpt_login flush $signal_name "$@"
        ;;
    await_migrations)
        echo Awaiting database migrations to be applied...
        while ! flask db current 2> /dev/null | grep '(head)'; do
            sleep 10
        done
        ;;
    *)
        exec "$@"
        ;;
esac
