import datetime
from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
from sql_alchemy import banco

from resources.hotel import Hoteis, Hotel
from resources.usuario import User, UserRegister, UserLogin, UserLogout, UserConfirm
from resources.site import Site, Sites
from blacklist import BLACKLIST
from settings_mysql import *


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://{USER}:{PW}@{HOST}/{DB}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'DontTellAnyone'
app.config['JWT_BLACKLIST_ENABLE'] = True
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(hours=2)

banco.init_app(app)
api = Api(app)
jwt = JWTManager(app)


@jwt.token_in_blocklist_loader
def verifica_blacklist(self, token):
    return token['jti'] in BLACKLIST


@jwt.revoked_token_loader
def token_acesso_invalidado(jwt_header, jwt_payload):
    return jsonify({'message': 'You have been logged out.'}), 401


api.add_resource(Hoteis, '/hoteis')
api.add_resource(Hotel, '/hoteis/<string:hotel_id>')
api.add_resource(User, '/usuarios/<int:user_id>')
api.add_resource(UserRegister, '/cadastro')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogout, '/logout')
api.add_resource(UserConfirm, '/confirmacao/<int:user_id>')
api.add_resource(Sites, '/sites')
api.add_resource(Site, '/sites/<string:url>')

# remover no deploy
app.run(debug=True)
