import os
from flask import Flask, request, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, decode_token
from datetime import datetime, timedelta
from flask_mail import Mail, Message

app = Flask(__name__)

# Configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class EmailVerificationToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Routes
@app.route('/')
def home():
    return 'Welcome to the AI Guide App!'

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']

    # Check if the email already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify(message="Email already exists."), 400

    # Hash the password and create the new user
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    # Create a token for email verification
    token = create_access_token(identity=new_user.id, expires_delta=timedelta(hours=24))
    verification_url = url_for('verify_email', token=token, _external=True)

    # Send verification email
    msg = Message("Email Verification", sender=os.getenv('MAIL_USERNAME'), recipients=[email])
    msg.body = f'Click the link to verify your email: {verification_url}'
    mail.send(msg)

    return jsonify(message="User registered successfully! Please verify your email."), 201

@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    try:
        # Extract token from URL and verify it
        identity = decode_token(token)['sub']  # 'sub' contains the user ID
        user = User.query.get(identity)

        if user:
            if user.is_verified:
                return jsonify(message="Email is already verified."), 400

            user.is_verified = True
            db.session.commit()
            return jsonify(message="Email verified successfully!"), 200
        else:
            return jsonify(message="User not found"), 404
    except Exception:
        return jsonify(message="Invalid or expired token."), 400

if __name__ == '__main__':
    app.run(debug=True)