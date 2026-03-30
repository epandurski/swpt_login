Swaptacular service that manages OAuth2 login and consent
=========================================================

This project implements user registration, login, and authorization
consent for [Swaptacular]. The ultimate deliverable is a docker image,
which is generated from the project's
[Dockerfile](../master/Dockerfile).

**IMPORTANT NOTE: Organizations running Swaptacular debtors and
creditors agents are encouraged to use their own OAuth2 login and
consent implementations, which take into account their concrete
security and user management policies.**


Dependencies
------------

Containers started from the generated docker image must have access to
the following servers:

1. [PostgreSQL] server instance, which stores users' data.

2. [Ory Hydra] [OAuth 2.0] authorization server, which generates and
   verifies access tokens.

3. A [Redis]-compatible server instance, which stores more or less
   transient login data. For this kind of information, the tolerance
   for data loss is high, but nevertheless, the Redis-compatible
   server instance must be configured as persistent (on-disk)
   database.

4. A [Payments Web API] server (for creditors agent nodes), or a
   [Simple Issuing Web API] server (for debtors agent nodes). Users
   will be activated and deactivated by issuing HTTP requests to this
   server.

5. A [SMTP server], for sending emails.

To increase security and performance, it is highly recommended that
you configure HTTP reverse-proxy server(s) (like [nginx]) between your
clients and your login and Ory Hydra servers.


Configuration
-------------

The behavior of the running container can be tuned with environment
variables. Here are the most important settings with some random
example values:

```shell
# Set this to the base URL of ORY Hydra's admin API. Note that Ory
# Hydra 2.0 adds an "/admin/" prefix to all endpoints in the admin
# API. Therefore, for Ory Hydra < 2.0, the value of HYDRA_ADMIN_URL
# would be something like this: "http://hydra:4445/".
HYDRA_ADMIN_URL=http://hydra:4445/admin/

# The prefix added the user ID to form the Oauth2 subject field. Must be
# either "creditors:" or "debtors:". For example, if SUBJECT_PREFIX=creditors:,
# the OAuth2 subject for the user with ID=1234 would be "creditors:1234".
SUBJECT_PREFIX=debtors:

# The specified number of processes ("$WEBSERVER_PROCESSES") will be
# spawned to handle HTTP requests (default 1), each process will run
# "$WEBSERVER_THREADS" threads in parallel (default 3). The container
# will listen for HTTP requests on port "$WEBSERVER_PORT" (default 8080).
WEBSERVER_PORT=8000
WEBSERVER_PROCESSES=1
WEBSERVER_THREADS=3

# Optional path (only the path) to the login page. If not set,
# depending on the value of the SUBJECT_PREFIX variable, the default
# will be either "/creditors-login" or "/debtors-login". The path
# "${LOGIN_PATH}/healthz" can be used as readiness and liveness probe.
LOGIN_PATH=

# Optional path (only the path) to the consent page. If not set,
# depending on the value of the SUBJECT_PREFIX variable, the default
# will be either "/creditors-consent" or "/debtors-consent".
CONSENT_PATH=

# The URL for the PostgreSQL database that the login and consent apps should use.
POSTGRES_URL=postgresql+psycopg://swpt_login:swpt_login@localhost:5435/test

# Optional URL for a read-only replica of the master PostgreSQL
# database (specified by `POSTGRES_URL`). Using multiple
# read-only replicas behind a load-balancer may increase the number of
# user requests that a busy system can handle. If not set, the
# `POSTGRES_URL` will also be used for the read-only operations.
POSTGRES_REPLICA_URL=

# Optional upper limit on the number of PostgreSQL connections in the
# connection pool. If set to zero, which is the default value, there
# is no limit.
POSTGRES_CONNECTION_POOL_SIZE=100

# Set this to the URL for the Redis-compatible server instance which
# the login and consent apps should use. It is highly recommended that
# your Redis-compatible instance is backed by disk storage. If not so,
# your users might be inconvenienced when your Redis instace is
# restarted.
REDIS_URL=redis://redis:6379/0

# Optional URL for one of the nodes of the Redis Cluster which the
# login and consent apps should use, instead of using a single Redis
# server instance. If set, `REDIS_URL` will be ingored. When
# connecting to a Redis Cluster, usually it is a good idea to specify
# more than one cluster node. In practice, however, a Kubernetes
# service will always be used. "redis://my-cluster-service:30001/0"
# for example.
REDIS_CLUSTER_URL=

# Set this to the name of your site, as it is known to your users.
SITE_TITLE=Demo Debtors Agent

# Set this to an URL that tells more about your site.
ABOUT_URL=https://example.com/about

# Optional URL to go to, after a successful sign-up. Note that setting
# this will greatly improve users' experience!
SIGNED_UP_REDIRECT_URL=

# Optional URL for users to go to, to recover their wrongfully
# suspended accounts. This is not needed if no user accounts have
# ever been suspended.
SUSPENDED_ACCOUNT_HELP_URL=https://example.com/help

# The name of the CSS style-sheet that will be used. Currently, the
# available names are "default" and "alt1". The default style-sheet
# name is "default".
STYLE_NAME=default

# Optional URL for a custom CSS style-sheet. If set, STYLE_NAME will
# be ignored.
STYLE_URL=

# SMTP server connection parameters. You should set MAIL_SERVER to the
# name of your mail server, and MAIL_PORT to the SMTP port on that
# server. MAIL_DEFAULT_SENDER should be set to the email address from
# which outgoing emails will be sent to users. Do not set
# MAIL_USERNAME and MAIL_PASSWORD if the SMPT server does not require
# username and password (you can also set them to empty strings).
# MAIL_USE_SSL detemines whether SSL is required from the beginning
# (default "False"), and MAIL_USE_TLS determines whether the STARTTLS
# extension should be used after the connection to the mail server has
# bee established (default "False").
MAIL_SERVER=my-mail-server
MAIL_PORT=25
MAIL_DEFAULT_SENDER=Demo Debtors Agent <no-reply@example.com>
MAIL_USERNAME=smtp_user
MAIL_PASSWORD=smpt_password
MAIL_USE_SSL=False
MAIL_USE_TLS=False

# When set to "False" (the default is "True"), does not allow new
# user registrations.
ALLOW_SIGNUP=True

# When set to "False" (the default is "True"), does not show any
# CAPTCHAs. Normally, this should be "True".
SHOW_CAPTCHA_ON_SIGNUP=True

# Parameters for hCaptcha. Required if SHOW_CAPTCHA_ON_SIGNUP is
# "True". You should obtain your own "sitekey"/"sitekey secret" pair
# from https://www.hcaptcha.com/, and put it here. Note that the
# "sitekey secret" should be kept secret.
CAPTCHA_SITEKEY=10000000-ffff-ffff-ffff-000000000001
CAPTCHA_SITEKEY_SECRET=0x0000000000000000000000000000000000000000

# When set to "False" (the default is "True"), does not show any
# ALTCHAs (see https://altcha.org/). Normally, this should be "True".
SHOW_ALTCHA_ON_LOGIN=True

# Parameters for ALTCHA. Required if SHOW_ALTCHA_ON_LOGIN is "True".
# ALTCHA_SECRET_HMAC_KEY should be set to a cryptogaphically strong
# secret string. ALTCHA_MAX_NUMBER is proportional to the
# computational effort needed to solve the ALTCHA challenge (default
# 100000). ALTCHA_INFO_URL is an URL that tells the users what ALTCHA
# is (default "https://altcha.org/"). ALTCHA_EXPIRATION_SECONDS
# determines the expiration interval of each challenge (default 3600
# seconds).
ALTCHA_SECRET_HMAC_KEY=some-long-and-secret-string
ALTCHA_MAX_NUMBER=50000
ALTCHA_INFO_URL=https://altcha.org/
ALTCHA_EXPIRATION_SECONDS=1800

# Parameters that determine how to obtain an user ID from the resource
# server. "$SUPERUSER_CLIENT_ID" and "$SUPERUSER_CLIENT_SECRET" are
# used to perform the "Client Credentials" OAuth2 flow against the
# OAuth2 token endpoint ("$API_AUTH2_TOKEN_URL"), so as to get the
# permissions to create and deactivate users. New users will be
# created and deactivated by sending requests to
# "$API_RESOURCE_SERVER". The timeout for the Web API requests will be
# "$API_TIMEOUT_SECONDS" seconds (default 5).
SUPERUSER_CLIENT_ID=debtors-superuser
SUPERUSER_CLIENT_SECRET=debtors-superuser
API_AUTH2_TOKEN_URL=https://my-nginx-ingress/debtors-hydra/oauth2/token
API_RESOURCE_SERVER=https://my-nginx-ingress
API_TIMEOUT_SECONDS=5

# Settings for the `flush_*` commands. The specified number of
# processes ("$FLUSH_PROCESSES") will be spawned to process pending
# tasks (default 1). Note that FLUSH_PROCESSES can be set to 0, in
# which case, the container will not process any pending tasks. The
# "$FLUSH_PERIOD" value specifies the number of seconds to wait
# between two sequential database queries for obtaining pending tasks
# (default 2).
FLUSH_PROCESSES=2
FLUSH_PERIOD=1.5

# Set the minimum level of severity for log messages ("info",
# "warning", or "error"). The default is "warning".
APP_LOG_LEVEL=info

# Set format for log messages ("text" or "json"). The default is
# "text".
APP_LOG_FORMAT=text
```

Available commands
------------------

The [entrypoint](../master/docker/entrypoint.sh) of the docker
container allows you to execute the following *documented commands*:

* `configure`

  Initializes a new empty PostgreSQL database for the login Web
  server.

  **IMPORTANT NOTE: This command has to be run only once (at the
  beginning), but running it multiple times should not do any harm.**

* `webserver`

  Starts a login Web server. This command allows you to start as many
  web servers as necessary, to handle the incoming load. Also, this is
  the command that will be executed if no arguments are passed to the
  entrypoint.

  **IMPORTANT NOTE: You must start at least one container with this
  command.**

* `flush_activate_users`

  Starts a process that periodically processes unprocessed rows from
  the *activate_user_signal* table. When some Web server process is
  unexpectedly terminated, some rows in that table may remain
  unprocessed. This command will take care of them.

  **IMPORTANT NOTE: You must start at least one container with this
  command. Normally, one container should be enough.**

* `flush_deactivate_users`

  Starts a process that periodically processes unprocessed rows from
  the *deactivate_user_signal* table. When a user decides to delete
  his/her account, a row is added to that table. This command
  finalizes the user deactivation process.

  **IMPORTANT NOTE: You must start at least one container with this
  command. Normally, one container should be enough.**

* `await_migrations`

  Blocks until the latest migration applied to the PostgreSQL server
  instance matches the latest known migration.


How to run the tests
--------------------

1.  Install [Docker Engine] and [Docker Compose].

2.  To create an *.env* file with reasonable defalut values, run this
    command:

        $ cp development.env .env

3.  To run the unit tests, use the following commands:

        $ docker-compose build
        $ docker-compose run tests-config test


How to setup a development environment
--------------------------------------

1.  Install [Poetry](https://poetry.eustace.io/docs/).

2.  Create a new [Python](https://docs.python.org/) virtual
    environment and activate it.

3.  To install dependencies, run this command:

        $ poetry install

4.  To run the minimal set of services needed for development, use
    this command:

        $ docker-compose up --build

    This will start its own PostgreSQL, Redis, and Mail server
    instances in docker containers. However, an Ory Hydra server, and
    a creditor/debtor resource server will NOT be stated.

5.  You can use `flask run -p 5000` to run a local web server, and
    `pytest --cov=swpt_login --cov-report=html` to run the tests and
    generate a test coverage report.


How to run all services together (production-like)
--------------------------------------------------

This [docker-compose
example](https://github.com/swaptacular/swpt_debtors/blob/master/docker-compose-all.yml)
shows how the generated docker image can be used along with the other
parts of the system.


[Swaptacular]: https://swaptacular.github.io/overview
[ORY Hydra]: https://www.ory.sh/hydra/docs/
[Debtors Agent]: https://github.com/swaptacular/swpt_debtors
[Creditors Agent]: https://github.com/swaptacular/swpt_creditors
[Swaptacular Messaging Protocol]: https://github.com/swaptacular/swpt_accounts/blob/master/protocol.rst
[PostgreSQL]: https://www.postgresql.org/
[nginx]: https://en.wikipedia.org/wiki/Nginx
[OAuth 2.0]: https://oauth.net/2/
[Ory Hydra]: https://www.ory.sh/hydra/
[Redis]: https://redis.io/
[Docker Engine]: https://docs.docker.com/engine/
[Docker Compose]: https://docs.docker.com/compose/
[Payments Web API]: https://swaptacular.github.io/public/docs/swpt_creditors/redoc.html
[Simple Issuing Web API]: https://swaptacular.github.io/public/docs/swpt_debtors/redoc.html
[SMTP server]: https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol
