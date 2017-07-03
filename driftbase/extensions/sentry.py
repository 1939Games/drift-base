from raven.contrib.flask import Sentry

def register_extension(app):
    app.sentry = Sentry(app)
