from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
import random
import jwt
import time

from urllib3.packages.six import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
# секретный ключ, которым мы шифруем данные
app.config['SECRET_KEY'] = 'secret'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    last_generation = db.Column(db.Integer, nullable=True)


def requires_user(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # получаем токен из заголовков запроса
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        # если токена нет - возвращаем ошибку
        if not token:
            return jsonify({'error': 'Missing token'}), 401

        # расшифровываем токен и получаем его содержимое
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401

        # получаем id пользователя и время генерации из токена
        user_id = payload.get('user_id')
        created_at = payload.get('created_at')

        # если чего-то нет - возвращаем ошибку
        if not user_id or not created_at:
            return jsonify({'error': 'Invalid token'}), 401

        # находим пользователя, если его нет - возвращаем ошибку
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 401

        # если с момента генерации прошло больше суток, просим войти заного
        if created_at + 60 * 60 * 24 < int(time.time()):
            return jsonify({'error': 'Token expired'}), 401

        # передаем в целевой эндпоинт пользователя и параметры пути
        return func(user, *args, **kwargs)

    return wrapper

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({'error': 'Missing data'}), 400

    if User.query.filter_by(login=login).first():
        return jsonify({'error': 'User already exists'}), 400

    # заменяем пароль на хэш пароля
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(login=login, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': True}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({'error': 'Missing data'}), 400

    # ищем пользователя в базе и проверяем хэш пароля
    user = User.query.filter_by(login=login).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # генерируем токен с id пользователя и временем создания
    token = jwt.encode({'user_id': user.id, 'created_at': int(time.time())}, app.config['SECRET_KEY'],
                       algorithm='HS256')

    return jsonify({'token': token}), 200


# добавляем декоратор @requires_user, который проверит токен и передаст параметром пользователя
@app.route('/api/generate', methods=['GET'])
@requires_user
def generate_number(user):
    # если пользователь посылает запросы чаще раза в секунду - отправляем ошибку
    if user.last_generation == int(time.time()):
        return jsonify({'error': 'Too many request per second'}), 401

    user.last_generation = int(time.time())
    db.session.commit()

    return jsonify({'number': random.randint(1, 1000000)}), 200


if __name__ == '__main__':
    app.run(debug=True, port=8000)
