from flask import Flask, request, jsonify, send_file
import mysql.connector
import os
from functools import wraps
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'


# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='root1234@',
        database='dbname'
    )


# Helper functions
def generate_token(email, is_ops_user):
    """
    Generates a JWT token with email and is_ops_user claims.
    """
    payload = {
        'email': email,
        'is_ops_user': is_ops_user,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Token expiration time (1 hour)
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')


def decode_token(token):
    """
    Decodes and verifies the JWT token.
    """
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token


def token_required(f):
    """
    Decorator function to check for valid JWT token in headers.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify(message='Token is missing!'), 401

        token = token.split()[1]  # Extract token from "Bearer token"
        decoded_token = decode_token(token)

        if not decoded_token:
            return jsonify(message='Token is invalid!'), 401

        # Pass decoded token data (claims) to the route function
        return f(decoded_token, *args, **kwargs)

    return decorated_function

@app.get("/welcome")
def welcome():
    return "Welcome to File Sharing System!!!!"


# Routes
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data['email']
    password = data['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (email, password, is_ops_user) VALUES (%s, %s, %s)', (email, password, False))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify(message="User created"), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password, is_ops_user FROM users WHERE email = %s', (email,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result and password == result[0]:
        token = generate_token(email, result[1])
        return jsonify(token=token), 200
    return jsonify(message="Invalid credentials"), 401


@app.route('/upload-file', methods=['POST'])
@token_required
def upload_file(decoded_token):
    email = decoded_token['email']
    is_ops_user = decoded_token['is_ops_user']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT is_ops_user FROM users WHERE email = %s', (email,))
    result = cursor.fetchone()

    if not result[0]:
        return jsonify(message="Operation not permitted"), 403

    file = request.files['file']
    if not file.filename.endswith(('.pptx', '.docx', '.xlsx')):
        return jsonify(message="Invalid file type"), 400

    file_path = os.path.join("files", file.filename)
    file.save(file_path)

    cursor.execute('INSERT INTO files (filename, file_path, uploaded_by) VALUES (%s, %s, %s)',
                   (file.filename, file_path, email))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify(message="File uploaded"), 201


@app.route('/files', methods=['GET'])
@token_required
def list_files(decoded_token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, filename FROM files')
    files = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify([{'id': file[0], 'filename': file[1]} for file in files]), 200


@app.route('/download-file/<int:file_id>', methods=['GET'])
@token_required
def download_file(decoded_token, file_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT file_path FROM files WHERE id = %s', (file_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if not result:
        return jsonify(message="File not found"), 404

    token = generate_token(result[0], False)  # Token for file access
    return jsonify(download_link=token), 200


@app.route('/access-file/<path:encrypted_url>', methods=['GET'])
@token_required
def access_file(decoded_token, encrypted_url):
    try:
        decoded_token = decode_token(encrypted_url)
        file_path = decoded_token['file_path']
        return send_file(file_path)
    except:
        return jsonify(message="Invalid or expired link"), 400


if __name__ == '__main__':
    app.run(debug=True)
