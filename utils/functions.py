from flask import request, jsonify
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv
import datetime, jwt, os

load_dotenv()

def encode_auth_token(payload):
    try:
        SECRET_KEY = os.getenv('SECRET_KEY')
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            'iat': datetime.datetime.utcnow(),
            'sub': payload
        }
        
        return jwt.encode(
            payload,
            SECRET_KEY,
            algorithm='HS256'
        )
    except Exception as e:
        return e

def decode_auth_token(token):
    try:
        SECRET_KEY = os.getenv('SECRET_KEY')
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please login again'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please login again'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization']

        if not token:
            return jsonify({'msg': 'Token is missing'}), 401
        
        try:
            data = decode_auth_token(token)
            if isinstance(data, str):
                return jsonify({'msg': data}), 401
            request.user = data['sub']
        except Exception as e:
            return jsonify({'msg': str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated