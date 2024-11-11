import time
from flask import Blueprint, request, session
from flask import render_template, redirect, jsonify
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from .models import db, User, OAuth2Client
from .oauth2 import authorization, require_oauth, generate_user_info
import os
import hashlib


bp = Blueprint('bp', 'home')

def hash_password(password: str) -> bytes:
    # Convert the password to bytes
    password_bytes = password.encode('utf-8')
    
    # Generate a random salt
    salt = os.urandom(16)  # 16 bytes is recommended
    
    # Hash the password using scrypt
    hashed = hashlib.scrypt(
        password_bytes,
        salt=salt,
        n=16384,  # CPU cost factor (must be a power of 2, typically 16384 or higher)
        r=8,      # Block size factor
        p=1,      # Parallelization factor
        dklen=64  # Length of derived key in bytes
    )
    
    # Return the salt + hash (store both to verify later)
    return salt + hashed

def verify_password(stored_password: bytes, password_attempt: str) -> bool:
    # Split the salt and the hash
    salt = stored_password[:16]
    stored_hash = stored_password[16:]
    
    # Hash the password attempt with the same salt
    attempt_hash = hashlib.scrypt(
        password_attempt.encode('utf-8'),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=64
    )
    
    # Check if the hashes match
    return attempt_hash == stored_hash


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


@bp.route('/sign_up', methods=('GET', 'POST'))
def sign_up():
    user = current_user()
    if user:
        return redirect('/')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if len(password) <= 0:
            return render_template('sign_up.html', error="Password must be greater then 0")
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, password=hash_password(password))
            db.session.add(user)
            db.session.commit()
        else:
            return render_template('sign_up.html', error="User exists")
        session['id'] = user.id
        return redirect('/')
    return render_template('sign_up.html', user=user)

@bp.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user:
            return render_template('home.html', error="Invalid username or password")
        if not verify_password(user.password, password):
            return render_template('home.html', error="Invalid username or password")
        session['id'] = user.id
        return redirect('/')
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []
    return render_template('home.html', user=user, clients=clients)


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]

@bp.route('/logout', methods=('GET', 'POST'))
def logout():
    session.clear()
    return redirect('/')

@bp.route('/edit_user', methods=('GET', 'POST'))
def edit_user():
    user = current_user()
    if not user:
        return redirect('/')

    if request.method == 'GET':
        return render_template('edit_user.html', user=user)

    form = request.form
    user.name = form['name']
    user.email = form['email']
    user.photo_url = form['photo_url']

    db.session.commit()
    return redirect('/')


@bp.route('/create_client', methods=('GET', 'POST'))
def create_client():
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        return render_template('create_client.html')
    form = request.form
    client_id = gen_salt(24)
    client = OAuth2Client(client_id=client_id, user_id=user.id)
    # Mixin doesn't set the issue_at date
    client.client_id_issued_at = int(time.time())
    if client.token_endpoint_auth_method == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)
    db.session.add(client)
    db.session.commit()
    return redirect('/')


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user()
    if request.method == 'GET':
        try:
            grant = authorization.validate_consent_request(end_user=user)
        except OAuth2Error as error:
            return jsonify(dict(error.get_body()))
        return render_template('authorize.html', user=user, grant=grant)
    if not user and 'username' in request.form:
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
    if request.form['confirm']:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth/userinfo')
@require_oauth('profile')
def api_me():
    return jsonify(generate_user_info(current_token.user, current_token.scope))
