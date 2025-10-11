import ssl
import pyotp
import qrcode
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, request, jsonify, session, render_template, redirect
import os, webauthn, json, io, base64
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    RegistrationCredential, PublicKeyCredentialDescriptor, AuthenticationCredential, AuthenticatorAttestationResponse,
    AuthenticatorAttachment, AuthenticatorAssertionResponse
)

from models.user import User, db
import hash_utils

app = Flask(__name__, instance_relative_config=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

load_dotenv()
fernet_key = os.environ['KEY']
fernet = Fernet(fernet_key)

app.secret_key = os.environ['FLASK_SECRET_KEY']


@app.route('/', methods=['GET', 'POST'])
def start():
    registered = request.args.get('registered')
    return render_template('start.html', registered=registered)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    return render_template('dashboard.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    # Extracting data from the HTTP request
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long.'}), 400

    password_hash = hash_utils.create_hash(password)

    # check if username already exist
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Provided username is already registered.'}), 400

    # check if email already exist
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Provided email is already registered.'}), 400

    try:
        response_obj = AuthenticatorAttestationResponse(
            attestation_object=webauthn.helpers.base64url_to_bytes(data['response']['attestationObject']),
            client_data_json=webauthn.helpers.base64url_to_bytes(data['response']['client_data_json']),
        )

        credential = RegistrationCredential(
            id=data['id'],
            raw_id=webauthn.helpers.base64url_to_bytes(data['raw_id']),
            type=data['type'],
            response=response_obj
        )

        client_data_json = webauthn.helpers.base64url_to_bytes(data['response']['client_data_json'])
        client_data = json.loads(client_data_json)

        verification = webauthn.verify_registration_response(
            credential=credential,
            expected_origin='https://localhost:5000',
            expected_rp_id='localhost',
            expected_challenge=webauthn.helpers.base64url_to_bytes(
                json.loads(session['registration_options'])['challenge']),
            require_user_verification=True,
        )
    except Exception as e:
        return jsonify({'message': str(e)}), 400

    webauthn_id = session['register_user_id']
    webauthn_public_key = verification.credential_public_key

    # Adding new user
    secret = pyotp.random_base32()
    totp_secret = fernet.encrypt(secret.encode())

    user = User(
        username,
        email,
        password_hash,
        webauthn_id=data['raw_id'],
        webauthn_public_key=webauthn_public_key,
        totp_secret=totp_secret
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'Registration completed successfully.'}), 201


@app.route('/register/webauthn', methods=['POST'])
def register_webauthn():
    data = request.json
    username = data.get('username')
    email = data.get('email')

    wa_user_id = os.urandom(16)
    wa_options = webauthn.generate_registration_options(
        rp_id='localhost',
        rp_name='webauthn',
        user_id=wa_user_id,
        user_name=username,
        user_display_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment("platform")
        ),
        attestation=AttestationConveyancePreference.NONE
    )

    session['registration_options'] = webauthn.options_to_json(wa_options)
    session['register_user_id'] = webauthn.helpers.bytes_to_base64url(wa_user_id)
    session['register_username'] = username
    session['register_email'] = email

    return webauthn.options_to_json(wa_options)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not hash_utils.check(password, user.password_hash):
        return jsonify({'message': 'Invalid username or password.'}), 401

    try:
        response = data.get('response')
        credential = AuthenticationCredential(
            id=data.get('id'),
            raw_id=webauthn.helpers.base64url_to_bytes(data.get("raw_id")),
            response=AuthenticatorAssertionResponse(
                client_data_json=webauthn.helpers.base64url_to_bytes(response['client_data_json']),
                authenticator_data=webauthn.helpers.base64url_to_bytes(response['authenticator_data']),
                signature=webauthn.helpers.base64url_to_bytes(response['signature']),
                user_handle=webauthn.helpers.base64url_to_bytes(response['user_handle']) if response[
                    'user_handle'] else None,
            ),
            type=data.get('type')
        )
        webauthn.verify_authentication_response(
            credential=credential,
            expected_origin='https://localhost:5000',
            expected_rp_id='localhost',
            expected_challenge=webauthn.helpers.base64url_to_bytes(json.loads(session['auth_challenge'])['challenge']),
            require_user_verification=True,
            credential_public_key=user.webauthn_public_key,
            credential_current_sign_count=0,
        )
    except Exception as e:
        return jsonify({'message': str(e)}), 400

    session['user_id'] = user.user_id
    return jsonify({'message': 'Login successful'}), 200


@app.route('/login/webauthn', methods=['POST'])
def login_webauthn():
    data = request.json
    username = data.get('username')

    user = User.query.filter_by(username=username).first()
    if not user or not user.webauthn_id or not user.webauthn_public_key:
        return jsonify({'message': 'User not registered with WebAuthn'}), 400

    wa_options = webauthn.generate_authentication_options(
        rp_id='localhost',
        allow_credentials=[PublicKeyCredentialDescriptor(
            id=webauthn.helpers.base64url_to_bytes(user.webauthn_id),
        )],
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    session['auth_challenge'] = webauthn.options_to_json(wa_options)
    session['auth_username'] = username

    return webauthn.options_to_json(wa_options)


@app.route('/register/totp', methods=['POST'])
def register_totp():
    data = request.json
    username = data.get('username')

    user = User.query.filter_by(username=username).first()
    totp_secret = user.totp_secret

    if not totp_secret:
        return {"message": "User not found"}, 404

    secret = fernet.decrypt(totp_secret).decode()
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="ProjektBemsi"
    )

    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return jsonify({"qr": img_b64})


@app.route('/verify', methods=['POST'])
def verify_totp():
    data = request.json
    username = data.get('username')
    token = data.get('token')

    user = User.query.filter_by(username=username).first()
    totp_secret = user.totp_secret

    if not totp_secret:
        return jsonify({"message": "User not found"}), 404

    secret = fernet.decrypt(totp_secret).decode()
    totp = pyotp.TOTP(secret)

    if totp.verify(token):
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"message": "Invalid token"}), 401


@app.route('/logout')
def logout():
    session.clear()
    return render_template('start.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='certs/localhost.pem', keyfile='certs/localhost-key.pem')

    app.run(ssl_context=context, host='localhost', port=5000, debug=True)
