# -*- coding: utf-8 -*-
# Standard library imports...
import hashlib
import hmac
import logging
import logging.config
import json
import os
import yaml
import random
import re
from requests import exceptions
import string
import sys
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlparse

# Third-party imports...
from parameterized import parameterized
from dateutil import parser

# Local imports...
try:
    from .context import matrix_registration
except ModuleNotFoundError:
    from context import matrix_registration
from matrix_registration.config import Config
from matrix_registration.app import create_app
from matrix_registration.captcha import db

logger = logging.getLogger(__name__)

LOGGING = {
    "version": 1,
    "root": {
        "level": "NOTSET",
        "handlers": ["console"]
    },
    "formatters": {
        "precise": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "NOTSET",
            "formatter": "precise",
            "stream": "ext://sys.stdout"
        }
    }
}

GOOD_CONFIG = {
    'server_location': 'https://righths.org',
    'shared_secret': 'coolsharesecret',
    'admin_secret': 'coolpassword',
    'db': 'sqlite:///%s/tests/db.sqlite' % (os.getcwd(), ),
    'port': 5000,
    'password': {
        'min_length': 8
    },
    'logging': LOGGING
}

BAD_CONFIG1 = dict(  # wrong matrix server location -> 500
    GOOD_CONFIG.items(),
    server_location='https://wronghs.org',
)

BAD_CONFIG2 = dict(  # wrong admin secret password -> 401
    GOOD_CONFIG.items(),
    admin_secret='wrongpassword',
)

BAD_CONFIG3 = dict(  # wrong matrix shared password -> 500
    GOOD_CONFIG.items(),
    shared_secret='wrongsecret',
)

usernames = []
nonces = []
logging.config.dictConfig(LOGGING)


def mock_new_user(username):
    access_token = ''.join(
        random.choices(string.ascii_lowercase + string.digits, k=256))
    device_id = ''.join(random.choices(string.ascii_uppercase, k=8))
    home_server = matrix_registration.config.config.server_location
    username = username.rsplit(":")[0].split("@")[-1]
    user_id = "@{}:{}".format(username, home_server)
    usernames.append(username)

    user = {
        'access_token': access_token,
        'device_id': device_id,
        'home_server': home_server,
        'user_id': user_id
    }
    return user


def mocked__get_nonce(server_location):
    nonce = ''.join(
        random.choices(string.ascii_lowercase + string.digits, k=129))
    nonces.append(nonce)
    return nonce


def mocked_requests_post(*args, **kwargs):

    class MockResponse:

        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

        def raise_for_status(self):
            if self.status_code == 200:
                return self.status_code
            else:
                raise exceptions.HTTPError(response=self)

    # print(args[0])
    # print(matrix_registration.config.config.server_location)
    domain = urlparse(GOOD_CONFIG['server_location']).hostname
    re_mxid = r"^@?[a-zA-Z_\-=\.\/0-9]+(:" + \
              re.escape(domain) + \
              r")?$"
    location = '_synapse/admin/v1/register'

    if args[0] == '%s/%s' % (GOOD_CONFIG['server_location'], location):
        if kwargs:
            req = kwargs['json']
            if not req['nonce'] in nonces:
                return MockResponse(
                    {"'errcode': 'M_UNKOWN", "'error': 'unrecognised nonce'"},
                    400)

            mac = hmac.new(
                key=str.encode(GOOD_CONFIG['shared_secret']),
                digestmod=hashlib.sha1,
            )

            mac.update(req['nonce'].encode())
            mac.update(b'\x00')
            mac.update(req['username'].encode())
            mac.update(b'\x00')
            mac.update(req['password'].encode())
            mac.update(b'\x00')
            mac.update(b'admin' if req['admin'] else b'notadmin')
            mac = mac.hexdigest()
            if not re.search(re_mxid, req['username']):
                return MockResponse(
                    {
                        "'errcode': 'M_INVALID_USERNAME",
                        "'error': 'User ID can only contain" +
                        "characters a-z, 0-9, or '=_-./'"
                    }, 400)
            if req['username'].rsplit(":")[0].split("@")[-1] in usernames:
                return MockResponse(
                    {
                        'errcode': 'M_USER_IN_USE',
                        'error': 'User ID already taken.'
                    }, 400)
            if req['mac'] != mac:
                return MockResponse(
                    {
                        'errcode': 'M_UNKNOWN',
                        'error': 'HMAC incorrect'
                    }, 403)
            return MockResponse(mock_new_user(req['username']), 200)
    return MockResponse(None, 404)


class TokensTest(unittest.TestCase):

    def setUp(self):
        matrix_registration.config.config = Config(GOOD_CONFIG)
        app = create_app(testing=True)
        with app.app_context():
            app.config.from_mapping(
                SQLALCHEMY_DATABASE_URI=matrix_registration.config.config.db,
                SQLALCHEMY_TRACK_MODIFICATIONS=False)
            db.init_app(app)
            db.create_all()

        self.app = app

    def tearDown(self):
        os.remove(matrix_registration.config.config.db[10:])

    def test_captcha_valid(self):
        with self.app.app_context():
            test_captcha_gen = matrix_registration.captcha.CaptchaGenerator()
            test_captcha = test_captcha_gen.generate()
            # validate that the captcha is correct
            self.assertTrue(
                test_captcha_gen.validate(test_captcha['captcha_answer'],
                                          test_captcha['captcha_token']))
            # captcha can only be used once
            self.assertFalse(
                test_captcha_gen.validate(test_captcha['captcha_answer'],
                                          test_captcha['captcha_token']))

    def test_captcha_empty(self):
        with self.app.app_context():
            test_captcha_gen = matrix_registration.captcha.CaptchaGenerator()
            # no captcha should exist at this point
            self.assertFalse(test_captcha_gen.validate("", ""))
            test_captcha = test_captcha_gen.generate()
            # no empty captcha should have been created
            self.assertFalse(test_captcha_gen.validate("", ""))

    def test_captcha_clean(self):
        with self.app.app_context():
            test_captcha_gen = matrix_registration.captcha.CaptchaGenerator()
            valid_captcha = test_captcha_gen.generate()
            # validate a wrong captcha
            self.assertFalse(
                test_captcha_gen.validate("WRONG",
                                          valid_captcha['captcha_token']))
            # valid captcha should be removed when it was wrong
            self.assertFalse(
                test_captcha_gen.validate(valid_captcha['captcha_answer'],
                                          valid_captcha['captcha_token']))
            timeout = matrix_registration.captcha.CAPTCHA_TIMEOUT
            matrix_registration.captcha.CAPTCHA_TIMEOUT = 0
            try:
                valid_captcha = test_captcha_gen.generate()
                time.sleep(1)
                # captcha older than the timeout value should not be valid
                self.assertFalse(
                    test_captcha_gen.validate(valid_captcha['captcha_answer'],
                                              valid_captcha['captcha_token']))
            finally:
                matrix_registration.captcha.CAPTCHA_TIMEOUT = timeout


class ApiTest(unittest.TestCase):

    def setUp(self):
        matrix_registration.config.config = Config(GOOD_CONFIG)
        app = create_app(testing=True)
        with app.app_context():
            app.config.from_mapping(
                SQLALCHEMY_DATABASE_URI=matrix_registration.config.config.db,
                SQLALCHEMY_TRACK_MODIFICATIONS=False)
            db.init_app(app)
            db.create_all()
            self.client = app.test_client()
        self.app = app

    def tearDown(self):
        os.remove(matrix_registration.config.config.db[10:])

    @parameterized.expand(
        [['test1', 'test1234', 'test1234', True, 200],
         [None, 'test1234', 'test1234', True, 400],
         ['test2', None, 'test1234', True, 400],
         ['test3', 'test1234', None, True, 400],
         ['test4', 'test1234', 'test1234', False, 400],
         ['@test5:matrix.org', 'test1234', 'test1234', True, 200],
         ['@test6:wronghs.org', 'test1234', 'test1234', True, 400],
         ['test7', 'test1234', 'tet1234', True, 400],
         ['teüst8', 'test1234', 'test1234', True, 400],
         ['@test9@matrix.org', 'test1234', 'test1234', True, 400],
         ['test11@matrix.org', 'test1234', 'test1234', True, 400],
         ['', 'test1234', 'test1234', True, 400],
         [
             ''.join(random.choices(string.ascii_uppercase, k=256)),
             'test1234', 'test1234', True, 400
         ]])
    # check form validators
    @patch('matrix_registration.matrix_api._get_nonce',
           side_effect=mocked__get_nonce)
    @patch('matrix_registration.matrix_api.requests.post',
           side_effect=mocked_requests_post)
    def test_register(self, username, password, confirm, captcha, status,
                      mock_get, mock_nonce):
        matrix_registration.config.config = Config(GOOD_CONFIG)
        with self.app.app_context():
            matrix_registration.captcha.captcha = matrix_registration.captcha.CaptchaGenerator(
            )
            test_captcha = matrix_registration.captcha.captcha.generate()

            # replace matrix with in config set hs
            domain = urlparse(
                matrix_registration.config.config.server_location).hostname
            if username:
                username = username.replace("matrix.org", domain)

            if not captcha:
                test_captcha['captcha_answer'] = ""
            rv = self.client.post(
                '/register',
                data=dict(username=username,
                          password=password,
                          confirm=confirm,
                          captcha_answer=test_captcha['captcha_answer'],
                          captcha_token=test_captcha['captcha_token']))
            if rv.status_code == 200:
                account_data = json.loads(
                    rv.data.decode('utf8').replace("'", '"'))
                # print(account_data)
            self.assertEqual(rv.status_code, status)

    @patch('matrix_registration.matrix_api._get_nonce',
           side_effect=mocked__get_nonce)
    @patch('matrix_registration.matrix_api.requests.post',
           side_effect=mocked_requests_post)
    def test_register_wrong_hs(self, mock_get, mock_nonce):
        matrix_registration.config.config = Config(BAD_CONFIG1)

        with self.app.app_context():
            matrix_registration.captcha.captcha = matrix_registration.captcha.CaptchaGenerator(
            )
            test_captcha = matrix_registration.captcha.captcha.generate()
            rv = self.client.post(
                '/register',
                data=dict(username='username',
                          password='password',
                          confirm='password',
                          captcha_answer=test_captcha['captcha_answer'],
                          captcha_token=test_captcha['captcha_token']))
            self.assertEqual(rv.status_code, 500)

    @patch('matrix_registration.matrix_api._get_nonce',
           side_effect=mocked__get_nonce)
    @patch('matrix_registration.matrix_api.requests.post',
           side_effect=mocked_requests_post)
    def test_register_wrong_secret(self, mock_get, mock_nonce):
        matrix_registration.config.config = Config(BAD_CONFIG3)

        with self.app.app_context():
            matrix_registration.captcha.captcha = matrix_registration.captcha.CaptchaGenerator(
            )
            test_captcha = matrix_registration.captcha.captcha.generate()
            rv = self.client.post(
                '/register',
                data=dict(username='username',
                          password='password',
                          confirm='password',
                          captcha_answer=test_captcha['captcha_answer'],
                          captcha_token=test_captcha['captcha_token']))
            self.assertEqual(rv.status_code, 500)


class ConfigTest(unittest.TestCase):

    def test_config_update(self):
        matrix_registration.config.config = Config(GOOD_CONFIG)
        self.assertEqual(matrix_registration.config.config.port,
                         GOOD_CONFIG['port'])
        self.assertEqual(matrix_registration.config.config.server_location,
                         GOOD_CONFIG['server_location'])

        matrix_registration.config.config.update(BAD_CONFIG1)
        self.assertEqual(matrix_registration.config.config.port,
                         BAD_CONFIG1['port'])
        self.assertEqual(matrix_registration.config.config.server_location,
                         BAD_CONFIG1['server_location'])

    def test_config_path(self):
        # BAD_CONFIG1_path = "x"
        good_config_path = "tests/test_config.yaml"

        with open(good_config_path, 'w') as outfile:
            yaml.dump(GOOD_CONFIG, outfile, default_flow_style=False)

        matrix_registration.config.config = Config(good_config_path)
        self.assertIsNotNone(matrix_registration.config.config)
        os.remove(good_config_path)


# TODO: - tests for /token/<token>
#       - a nonce is only valid for 60s

if "logging" in sys.argv:
    logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':
    unittest.main()
