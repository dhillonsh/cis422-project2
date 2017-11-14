import pytest
import json
import lib.MongoAddressClient as db
import lib.secrets.client_secrets as client_secrets
import lib.secrets.admin_secrets as admin_secrets
import sys, os, tempfile
import unittest

from lib.MongoAddressClient import MongoAddressClient
from lib.Security import SecureCipher

import CONFIG
import flask
from flask import redirect, request, url_for

try:
    MONGO_CLIENT = MongoAddressClient()
except Exception as exception:
    print(exception)
    print("Failure opening database. Is Mongo running? Correct password?")
    sys.exit(1)

CIPHER = SecureCipher(CONFIG.cipher_key)

APP = flask.Flask(__name__)
APP.secret_key = CONFIG.secret_key


class FlaskTestCase(unittest.TestCase):
    def setUp(self):
        self.db_fd, flask.app.config['DATABASE'] = tempfile.mkstemp()
        flask.app.testing = True
        self.app = flask.app.test_client()
        with flask.app.app_context():
            flask.init_db()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(flask.app.config['DATABASE'])

    def test_empty_db(self):
        rv = self.app.get('/')
        assert b'No entries here so far' in rv.data
