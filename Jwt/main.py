from flask import Flask, request, jsonify, make_response
import jwt
import datetime
from functools import wraps
import secrets

app = Flask(__name__)

# Generate a random secret key
# app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generates a 32-character hex string
app.config['SECRET_KEY'] = '43b6e4844b6d43d86ca7e8dfb53fb2e2'
# REAL IMPLEMENTATION : Load secret key from environment variable or configuration file
# app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# Dummy user data
users = {
    "tester": "test_password"
}


# Decorator to check for valid JWT token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-tokens')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
        except Exception as e:
            print(e)
            return jsonify({'message': 'Token is invalid!'}), 403

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/login', methods=['POST'])
def login():
    auth = request.form
    username = auth.get('username')
    password = auth.get('password')

    if not username or not password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if users.get(username) == password:
        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    return jsonify({'message': f'Hello, {current_user}! This is a protected route.'})


if __name__ == '__main__':
    app.run(debug=True)
