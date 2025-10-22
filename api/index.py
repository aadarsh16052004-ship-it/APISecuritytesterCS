from flask import Flask
from src.templates.app import app as flask_app

# Required by Vercel – wraps Flask app
def handler(request, *args, **kwargs):
    return flask_app(request.environ, start_response)

# Expose app variable for Vercel
app = flask_app
