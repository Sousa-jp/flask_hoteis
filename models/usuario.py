from flask import request, url_for
from sql_alchemy import banco
from passlib.context import CryptContext
from requests import post


MAILGUN_DOMAIN = '........mailgin.org'
MAILGUN_API_KEY = 'key-........'
FROM_TITLE = 'NO-REPLY'
FROM_EMAIL = 'no-reply@restapi.com'


pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    default="pbkdf2_sha256",
    pbkdf2_sha256__default_rounds=32846
)


def hash_password(password):
    return pwd_context.hash(password)


def check_hashed_password(password, hashed):
    return pwd_context.verify(password, hashed)


class UserModel(banco.Model):
    __tablename__ = 'usuarios'

    user_id = banco.Column(banco.Integer, primary_key=True)
    login = banco.Column(banco.String(40), nullable=False, unique=True)
    senha = banco.Column(banco.String(300), nullable=False)
    email = banco.Column(banco.String(80), nullable=False, unique=True)
    ativado = banco.Column(banco.Boolean, default=False)

    def __init__(self, login, senha, email, ativado):
        self.login = login
        self.senha = hash_password(senha)
        self.email = email
        self.ativado = ativado

    def send_confirmation_email(self):
        url = request.url_root[:-1] + url_for('userconfirm', user_id=self.user_id)
        return post(
            f'https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages',
            auth=('api', MAILGUN_API_KEY),
            data={
                    'from': f'{FROM_TITLE} <{FROM_EMAIL}>',
                    'to': self.email,
                    'subject': 'Confirmação de cadastro',
                    'text': f'Confirme seu cadastro clicando no link a seguir: {url}',
                    'html': '<html><p>'
                            f'Confirme seu cadastro clicando no link a seguir: <a href="{url}">CONFIRMAR EMAIL</a>'
                            f'</p></html>'
            }
        )

    def json(self):
        return {
            'user_id': self.user_id,
            'login': self.login,
            'email': self.email,
            'senha': self.senha,
            'ativado': self.ativado
        }

    @classmethod
    def find_user(cls, user_id):
        user = cls.query.filter_by(user_id=user_id).first()
        if user:
            return user
        return None

    @classmethod
    def find_by_login(cls, login):
        user = cls.query.filter_by(login=login).first()
        if user:
            return user
        return None

    @classmethod
    def find_by_email(cls, email):
        user = cls.query.filter_by(email=email).first()
        if user:
            return user
        return None

    def save_user(self):
        banco.session.add(self)
        banco.session.commit()

    def delete_user(self):
        banco.session.delete(self)
        banco.session.commit()
