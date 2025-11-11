import os
import random
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_cors import CORS
from flask_mail import Mail, Message
from dotenv import load_dotenv

# --- CONFIGURATION ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(os.path.dirname(BASE_DIR), '.env'))

# Serve frontend static files (HTML/JS/CSS) from the sibling `frontend/` directory
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), 'frontend')
app = Flask(__name__, static_folder=FRONTEND_DIR, template_folder=FRONTEND_DIR)
CORS(app)

# Environment-based configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_strong_secret_key_here')

# Database Configuration - Works on localhost and Render
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL:
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    DB_PATH = os.path.join(BASE_DIR, 'students.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration - Flask-Mail
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
# MAIL_USE_TLS may be set as a string in the environment (e.g. "true"),
# so normalize it to a boolean here.
mail_use_tls_env = os.getenv('MAIL_USE_TLS', 'True')
app.config['MAIL_USE_TLS'] = str(mail_use_tls_env).lower() in ('1', 'true', 'yes', 'on')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@tii.com')

mail = Mail(app)
db = SQLAlchemy(app)

# --- GLOBAL CONSTANTS ---
# Primary admin email used for admin token routing and notifications
ADMIN_RECIPIENT_EMAIL = os.getenv('ADMIN_EMAIL', 'codestiiwebadmin@gmail.com')
ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')  # 'development' or 'production'

# --- MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    role = db.Column(db.String(20), default='student', nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(100), db.ForeignKey('user.email'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

# --- UTILITIES ---
def send_email(email, subject, body):
    """
    Send email via Flask-Mail for production (Render).
    Falls back to mock email for localhost development.
    """
    # Use a background thread to avoid blocking the request/response cycle.
    def _send():
        if ENVIRONMENT == 'production' and app.config['MAIL_USERNAME']:
            try:
                msg = Message(
                    subject=subject,
                    recipients=[email],
                    body=body,
                    sender=app.config['MAIL_DEFAULT_SENDER']
                )
                mail.send(msg)
                print(f"✓ Email sent to {email}", flush=True)
            except Exception as e:
                print(f"✗ Email send failed: {e}", flush=True)
                # Still log the OTP for debugging
                print(f"OTP Code: {body}", flush=True)
        else:
            # Mock email sender for localhost or when MAIL_USERNAME isn't configured
            print("-" * 25 + " MOCK EMAIL SENDER " + "-" * 25, flush=True)
            print(f"To: {email}", flush=True)
            print(f"Subject: {subject}", flush=True)
            print(f"Body: {body}", flush=True)
            print("-" * 65, flush=True)

    try:
        import threading
        t = threading.Thread(target=_send, daemon=True)
        t.start()
    except Exception:
        # Fallback to synchronous send if threading isn't available
        _send()

def generate_otp():
    return str(random.randint(100000, 999999))

# --- ROUTES ---
@app.route('/')
def index_route():
    # If the frontend `index.html` exists, serve it so the site loads in a browser.
    index_path = os.path.join(FRONTEND_DIR, 'index.html')
    if os.path.exists(index_path):
        return app.send_static_file('index.html')

    # Fallback JSON for API-only deployments
    return jsonify({"message": "Backend Server is Running."}), 200


# Serve other static frontend assets (JS, CSS, images, etc.) when requested.
@app.route('/<path:filename>')
def serve_frontend(filename):
    file_path = os.path.join(FRONTEND_DIR, filename)
    if os.path.exists(file_path):
        return send_from_directory(FRONTEND_DIR, filename)
    # If not found as a static file, return a 404 JSON for API clients.
    return jsonify({'message': 'Not Found'}), 404

# --- REGISTRATION ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')

    if not all([full_name, email, password]):
        return jsonify({'message': 'Missing fields'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'An account with this email already exists.'}), 409

    try:
        role = 'admin' if User.query.count() == 0 else 'student'
        new_user = User(full_name=full_name, email=email, is_verified=False, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Generate and send OTP
        OTP.query.filter_by(user_email=email).delete()
        otp_code = generate_otp()
        expiration_time = datetime.utcnow() + timedelta(minutes=5)
        new_otp = OTP(user_email=email, code=otp_code, expires_at=expiration_time)
        db.session.add(new_otp)
        db.session.commit()

        send_email(
            email,
            "Your 6-Digit Verification Code",
            f"Your 6-digit verification code is: {otp_code}\n\nThis code expires in 5 minutes."
        )

        # Build response. In non-production (development/testing) include the OTP in the response
        response_payload = {
            'message': 'Registration successful. Verification code sent to your email.',
            'email': email
        }
        if ENVIRONMENT != 'production':
            response_payload['otp'] = otp_code

        return jsonify(response_payload), 201

    except Exception as e:
        db.session.rollback()
        print(f"Error during registration: {e}")
        return jsonify({'message': 'Internal server error during registration.'}), 500

# --- RESEND OTP ---
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()

    if not user or user.is_verified:
        return jsonify({'message': 'Account not found or already verified.'}), 400

    try:
        OTP.query.filter_by(user_email=email).delete()
        otp_code = generate_otp()
        expiration_time = datetime.utcnow() + timedelta(minutes=5)
        new_otp = OTP(user_email=email, code=otp_code, expires_at=expiration_time)
        db.session.add(new_otp)
        db.session.commit()

        send_email(
            email,
            "Your new 6-Digit Verification Code",
            f"Your new 6-digit verification code is: {otp_code}\n\nThis code expires in 5 minutes."
        )

        response_payload = {'message': 'New verification code sent to your email.'}
        if ENVIRONMENT != 'production':
            response_payload['otp'] = otp_code

        return jsonify(response_payload), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error during resend: {e}")
        return jsonify({'message': 'Internal server error during resend.'}), 500

# --- VERIFY OTP ---
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp_code = data.get('otp_code')

    if not all([email, otp_code]):
        return jsonify({'message': 'Missing email or OTP code'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404

    otp_entry = OTP.query.filter_by(user_email=email, code=otp_code) \
                         .filter(OTP.expires_at > datetime.utcnow()) \
                         .order_by(OTP.created_at.desc()) \
                         .first()

    if otp_entry:
        user.is_verified = True
        db.session.delete(otp_entry)
        db.session.commit()

        return jsonify({
            'message': 'Verification successful. Redirecting to portal...',
            'authToken': 'temp_secure_token',
            'full_name': user.full_name,
            'role': user.role
        }), 200
    else:
        return jsonify({'message': 'Invalid or expired verification code.'}), 401

# --- LOGIN ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        if not user.is_verified:
            return jsonify({
                'message': 'Account not verified. Redirecting to verification page.',
                'action': 'redirect_to_otp',
                'email': email
            }), 403

        return jsonify({
            'status': 'success',
            'message': 'Login successful.',
            'authToken': 'temp_secure_token',
            'full_name': user.full_name,
            'role': user.role
        }), 200

    return jsonify({'message': 'Invalid email or password.'}), 401

# --- ADMIN LOGIN CHECK ---
@app.route('/admin_login_check', methods=['POST'])
def admin_login_check():
    """Step 1: Check credentials and determine if token is needed."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid email or password.'}), 401

    if not user.is_verified:
        return jsonify({
            'message': 'Account not verified.',
            'action': 'redirect_to_otp',
            'email': email
        }), 403

    # Case 1: Already an Admin
    if user.role == 'admin':
        return jsonify({
            'status': 'success',
            'message': 'Admin login successful.',
            'authToken': 'temp_secure_token',
            'full_name': user.full_name,
            'role': user.role
        }), 200

    # Case 2: Not an Admin - Require Token
    if user.role == 'student':
        return jsonify({
            'status': 'requires_token',
            'message': 'Token required for admin access.',
            'email': email
        }), 403

# --- SEND ADMIN TOKEN ---
@app.route('/send_admin_token', methods=['POST'])
def send_admin_token():
    """Send token to primary admin email."""
    data = request.get_json()
    user_email = data.get('email')

    if not user_email:
        return jsonify({'message': 'Missing email parameter'}), 400

    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404

    try:
        OTP.query.filter_by(user_email=ADMIN_RECIPIENT_EMAIL).delete()
        token_code = generate_otp()
        expiration_time = datetime.utcnow() + timedelta(minutes=10)
        new_token = OTP(user_email=ADMIN_RECIPIENT_EMAIL, code=token_code, expires_at=expiration_time)
        db.session.add(new_token)
        db.session.commit()

        send_email(
            ADMIN_RECIPIENT_EMAIL,
            f"Admin Access Request from {user_email}",
            f"User {user_email} ({user.full_name}) is requesting admin access.\n\n"
            f"Approval token: {token_code}\n\n"
            f"This token expires in 10 minutes.\n\n"
            f"Share this token with the user only if approved."
        )

        return jsonify({
            'message': 'Token sent to admin email.',
            'admin_email': ADMIN_RECIPIENT_EMAIL
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error sending admin token: {e}")
        return jsonify({'message': 'Internal server error.'}), 500

# --- ADMIN LOGIN (FINAL) ---
@app.route('/admin_login', methods=['POST'])
def admin_login():
    """Step 2: Final verification with token."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    token = data.get('token')

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid email or password.'}), 401

    if user.role == 'admin':
        return jsonify({
            'status': 'success',
            'message': 'Admin login successful.',
            'authToken': 'temp_secure_token',
            'full_name': user.full_name,
            'role': user.role
        }), 200

    if not token:
        return jsonify({'message': 'Token required for admin access.'}), 403

    otp_entry = OTP.query.filter_by(user_email=ADMIN_RECIPIENT_EMAIL, code=token) \
                         .filter(OTP.expires_at > datetime.utcnow()) \
                         .order_by(OTP.created_at.desc()) \
                         .first()

    if otp_entry:
        user.role = 'admin'
        db.session.delete(otp_entry)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Admin access granted.',
            'authToken': 'temp_secure_token',
            'full_name': user.full_name,
            'role': user.role
        }), 200
    else:
        return jsonify({'message': 'Invalid or expired token.'}), 401

# --- SERVER SETUP ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    port = int(os.environ.get('PORT', 3000))
    debug_mode = ENVIRONMENT == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)