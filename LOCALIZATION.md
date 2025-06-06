# How to localize

*swpt_login* uses [babel](http://babel.pocoo.org/en/latest/) for
localization. Here are the most basic commands that you will probably
want to use (they all should be executed from the `swpt_login/`
directory):

## Extract all messages to `messages.pot`:

```
$ pybabel extract -F babel.cfg -k lazy_gettext -o messages.pot .
```

## Update all `.po` files from `messages.pot`

```
$ pybabel update -i messages.pot -d translations
```

## Compile all `.po` files to `.mo` files

```
$ pybabel compile -d translations
```

## Create translation for a new language:

```
$ pybabel init -i messages.pot -d translations -l de
```
