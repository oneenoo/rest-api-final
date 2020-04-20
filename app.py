import os

from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager

from resources.user import (
    UserRgister, User, UserLogin, UserLogout, TokenRefresh
)
from resources.item import Item, ItemList
from resources.store import Store, StoreList
from blacklist import BLACKLIST

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.secret_key = 'mrbl' # app.config['JWT_SECRET_KEY']
api = Api(app)

@app.before_first_request
def create_tables():
    db.create_all()

jwt = JWTManager(app) 

@jwt.user_claims_loader
# можно добавить произволные данные и параметры чтобы передать в методы.
def add_claims_to_jwt(identity):
    if identity == 1:
        return {'is admin': True}
    return {'is admin': False}

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    # return decrypted_token['identity'] in BLACKLIST
    return decrypted_token['jti'] in BLACKLIST

@jwt.expired_token_loader
# функция которая будет вызвана когда придет просроченный токен, 
# в среднем 5 мин. И какое сообщение будт отравлено пользователю.
def expired_token_loader():
    return jsonify({
        'description': 'The token has expired',
        'error': 'token_expired'
    }), 401

@jwt.invalid_token_loader
# Вызов если теле авторизации пришел не правильный токен, 
# или вообще рандомная строка
def invalid_token_callback(error):
    #return "What are you doing", 401
    return jsonify ({
        'description': 'Signature verification failed',
        'error': 'invalid_token'
    }), 401

@jwt.unauthorized_loader
# Вызов если теле токен вообще не пришел.
def missing_token_callback(error):
    return jsonify({
        'description': 'Request does not contain an acess token',
        'error': 'authorization_required'
    }), 401

@jwt.needs_fresh_token_loader
# Вызывается в случае если нам нужен 
# fresh токен(токен полученный при вводе логина и пароля)
# но к нам пришел non-fresh токен. прирмер в item post
def token_not_fresh_callback():
    return jsonify({
        'description': 'The token is not fresh.',
        'error': 'fresh_token_required'
    }), 401

@jwt.revoked_token_loader
# выполняется при необходимости отозвать токен пользователя.
# например когда пользователь вышел из системы.
def revoked_token_callback():
    return jsonify({
        'description': 'The token has been revoked.',
        'error': 'token_revoked'
    }), 401 

api.add_resource(Store, '/store/<string:name>')
api.add_resource(Item, '/item/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(StoreList, '/stores')
api.add_resource(UserRgister, '/register')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserLogin, '/login')
api.add_resource(TokenRefresh, '/refresh')
api.add_resource(UserLogout, '/logout')

if __name__ == '__main__':
    from db import db
    db.init_app(app)

    app.run(port=5000, debug=True)