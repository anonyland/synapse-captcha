# Standard library imports...
import logging
from requests import exceptions
import re
from urllib.parse import urlparse

# Third-party imports...
from flask import (Blueprint, abort, jsonify, request, make_response,
                   render_template)
from wtforms import (Form, StringField, PasswordField, validators)
from wtforms.fields.simple import HiddenField

# Local imports...
from .matrix_api import create_account
from . import config
from . import captcha

logger = logging.getLogger(__name__)

api = Blueprint("api", __name__)

re_mxid = re.compile(r'^@?[a-zA-Z_\-=\.\/0-9]+(:[a-zA-Z\-\.:\/0-9]+)?$')


def validate_captcha(form, captcha_answer):
    """
    validates captcha
    Parameters
    ----------
    arg1 : Form object
    arg2 : str
        captcha answer, e.g. '4tg'
    Raises
    -------
    ValidationError
        captcha is invalid
    """
    if not captcha.captcha.validate(captcha_answer.data,
                                    form.captcha_token.data):
        raise validators.ValidationError("captcha is invalid")


def validate_username(form, username):
    """
    validates username

    Parameters
    ----------
    arg1 : Form object
    arg2 : str
        username name, e.g: '@user:matrix.org' or 'user'
        https://github.com/matrix-org/matrix-doc/blob/master/specification/appendices/identifier_grammar.rst#user-identifiers
    Raises
    -------
    ValidationError
        Username doesn't follow mxid requirements
    """
    domain = urlparse(config.config.server_location).hostname
    re_mxid = r'^@?[a-zA-Z_\-=\.\/0-9]+(:' + \
              re.escape(domain) + \
              r')?$'
    err = "Username doesn't follow pattern: '%s'" % re_mxid
    if not re.search(re_mxid, username.data):
        raise validators.ValidationError(err)


def validate_password(form, password):
    """
    validates username

    Parameters
    ----------
    arg1 : Form object
    arg2 : str
        password
    Raises
    -------
    ValidationError
        Password doesn't follow length requirements
    """
    min_length = config.config.password['min_length']
    err = 'Password should be between %s and 255 chars long' % min_length
    if len(password.data) < min_length or len(password.data) > 255:
        raise validators.ValidationError(err)


class RegistrationForm(Form):
    """
    Registration Form

    validates user account registration requests
    """
    username = StringField(
        'Username',
        [
            validators.Length(min=1, max=200),
            # validators.Regexp(re_mxid)
            validate_username
        ])
    password = PasswordField(
        'New Password',
        [
            # validators.Length(min=8),
            validate_password,
            validators.DataRequired(),
            validators.EqualTo('confirm', message='Passwords must match')
        ])
    confirm = PasswordField('Repeat Password')
    captcha_answer = StringField("Captcha answer", [validate_captcha])
    captcha_token = HiddenField("Captcha token")


@api.route('/register', methods=['GET', 'POST'])
def register():
    """
    main user account registration endpoint
    to register an account you need to send a
    application/x-www-form-urlencoded request with
      - username
      - password
      - confirm
      - captcha_answer
      - captcha_token
     as described in the RegistrationForm
    """
    if request.method == 'POST':
        logger.debug('an account registration started...')
        form = RegistrationForm(request.form)
        logger.debug('validating request data...')
        if form.validate():
            logger.debug('request valid')
            # remove sigil and the domain from the username
            username = form.username.data.rsplit(':')[0].split('@')[-1]
            logger.debug('creating account %s...' % username)
            # send account creation request to the hs
            try:
                account_data = create_account(form.username.data,
                                              form.password.data,
                                              config.config.server_location,
                                              config.config.shared_secret)
            except exceptions.ConnectionError:
                logger.error('can not connect to %s' %
                             config.config.server_location,
                             exc_info=True)
                abort(500)
            except exceptions.HTTPError as e:
                resp = e.response
                error = resp.json()
                status_code = resp.status_code
                if status_code == 404:
                    logger.error('no HS found at %s' %
                                 config.config.server_location)
                elif status_code == 403:
                    logger.error(
                        'wrong shared registration secret or not enabled')
                elif status_code == 400:
                    # most likely this should only be triggered if a userid
                    # is already in use
                    return make_response(jsonify(error), 400)
                else:
                    logger.error('failure communicating with HS',
                                 exc_info=True)
                abort(500)
            logger.debug('account creation succeded!')
            return jsonify(access_token=account_data['access_token'],
                           home_server=account_data['home_server'],
                           user_id=account_data['user_id'],
                           status='success',
                           status_code=200)
        else:
            logger.debug('account creation failed!')
            captcha_data = captcha.captcha.generate()
            resp = {
                'errcode': 'MR_BAD_USER_REQUEST',
                'error': form.errors,
                "captcha_image": captcha_data["captcha_image"].decode(),
                "captcha_token": captcha_data["captcha_token"]
            }
            return make_response(jsonify(resp), 400)
            # for fieldName, errorMessages in form.errors.items():
            #     for err in errorMessages:
            #         # return error to user
    else:
        server_name = config.config.server_name
        pw_length = config.config.password['min_length']
        captcha_data = captcha.captcha.generate()
        return render_template(
            'register.html',
            server_name=server_name,
            pw_length=pw_length,
            riot_instance=config.config.riot_instance,
            base_url=config.config.base_url,
            captcha_token=captcha_data["captcha_token"],
            captcha_image=captcha_data["captcha_image"].decode())
