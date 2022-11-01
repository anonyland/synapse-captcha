from captcha.image import ImageCaptcha
from flask_sqlalchemy import SQLAlchemy

import base64
import random
import string
import time
import uuid

CAPTCHA_TIMEOUT = 5  # minutes
CAPTCHA_LENGTH = 5  # characters
CAPTCHA_WIDTH = 320
CAPTCHA_HEIGHT = 94

db = SQLAlchemy()


class Captcha(db.Model):
    __tablename__ = 'captcha'
    token = db.Column(db.String(36), primary_key=True)
    answer = db.Column(db.String(24))
    timestamp = db.Column(db.Integer, default=0)


class CaptchaGenerator:

    def clean(self):
        Captcha.query.filter(
            Captcha.timestamp < (time.time() - CAPTCHA_TIMEOUT * 60)).delete()
        db.session.commit()

    def validate(self, captcha_answer, captcha_token):
        self.clean()
        try:
            cpt = Captcha.query.filter(Captcha.token == captcha_token).one()
        except:
            # when the user stay on the page too long the captcha is removed
            return False

        if cpt:
            answer = cpt.answer
            db.session.delete(cpt)
            db.session.commit()
            return captcha_answer.lower() == answer
        return False

    def generate(self):
        self.clean()
        captcha_token = str(uuid.uuid4())
        captcha_answer = (''.join(
            random.choice(string.ascii_lowercase + string.digits)
            for _ in range(CAPTCHA_LENGTH)))
        image = ImageCaptcha(width=CAPTCHA_WIDTH, height=CAPTCHA_HEIGHT)
        captcha_image = base64.b64encode(
            image.generate(captcha_answer).getvalue())
        timestamp = time.time()
        data = {
            "captcha_image": captcha_image,
            "captcha_token": captcha_token,
            "captcha_answer": captcha_answer,
            "timestamp": timestamp
        }
        cpt = Captcha(token=captcha_token,
                      answer=captcha_answer,
                      timestamp=timestamp)
        db.session.add(cpt)
        db.session.commit()
        return data


captcha = None
