from flask import Flask, render_template, request, jsonify, url_for, redirect, session, flash
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import string
import re
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os
from functools import wraps
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

# Download NLTK resources
nltk.download('punkt')
nltk.download('stopwords')

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')  # Change this in production

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Email configuration
# Replace your current email config with this:
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ssohamm12@gmail.com'  # Your Gmail address
app.config['MAIL_PASSWORD'] = 'hczf earth chyt dcgq'  # Generated app password (see below)
app.config['MAIL_DEFAULT_SENDER'] = 'ssohamm12@gmail.com'  # Your Gmail address
app.config['MAIL_SUPPRESS_SEND'] = False  # Actually send emails
mail = Mail(app)



# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.String(20), default='user')

    def __repr__(self):
        return f'<User {self.username}>'
    
# Contact Message model
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<ContactMessage from {self.name}>'

# Create tables
with app.app_context():
    db.create_all()

# Load stopwords
ENGLISH_STOP_WORDS = set(stopwords.words("english"))

# Load the trained model
#model = tf.keras.models.load_model("model/EmailClassifierModel4.h5")
model = tf.keras.models.load_model("model/Trial.h5")

# Define tokenizer parameters
max_features = 5000
max_length = 500

# Load tokenizer
try:
    with open("model/label_encoder2.pkl", "rb") as handle:
        tokenizer = pickle.load(handle)
except:
    print("Warning: Tokenizer file not found! Using a new one.")
    tokenizer = Tokenizer(num_words=max_features)

# Text processing functions
def remove_special_characters(text):
    return text.translate(str.maketrans("", "", string.punctuation))

def remove_stop_words(tokens):
    return [word for word in tokens if word not in ENGLISH_STOP_WORDS]

def remove_hyperlink(text):
    return re.sub(r"http\S+", "", text)

def preprocess_text(text):
    text = text.lower()
    text = remove_special_characters(text)
    text = remove_hyperlink(text)
    tokens = word_tokenize(text)
    tokens = remove_stop_words(tokens)
    return " ".join(tokens)

# Authentication helper functions
def send_verification_email(user):
    token = generate_verification_token(user.email)
    verify_url = url_for('verify_email', token=token, _external=True)
    
    msg = Message('Verify Your Email - SpamGuard',
                 recipients=[user.email])
    
    # More professional email content
    msg.body = f'''Thank you for registering with SpamGuard!
    
Please verify your email address by clicking the following link:
{verify_url}

If you didn't request this, please ignore this email.

---
SpamGuard Team
'''
    # HTML version for better appearance
    msg.html = f'''
    <h1>SpamGuard Email Verification</h1>
    <p>Thank you for registering with SpamGuard!</p>
    <p>Please click the button below to verify your email address:</p>
    <a href="{verify_url}" style="
        background-color: #4CAF50;
        color: white;
        padding: 10px 20px;
        text-decoration: none;
        border-radius: 5px;
        display: inline-block;
    ">Verify Email</a>
    <p>Or copy this link: {verify_url}</p>
    <p>If you didn't request this, please ignore this email.</p>
    <hr>
    <p>SpamGuard Team</p>
    '''
    
    try:
        mail.send(msg)
        app.logger.info(f"Verification email sent to {user.email}")
    except Exception as e:
        app.logger.error(f"Failed to send verification email: {str(e)}")
        flash('Failed to send verification email. Please try again later.', 'error')


def send_password_reset_email(user):
    token = generate_password_reset_token(user.email)
    reset_url = url_for('reset_password', token=token, _external=True)
    
    # Debug print (for terminal testing)
    if app.debug:
        print(f"DEBUG: Password reset link for {user.email}: {reset_url}")
    
    # Skip sending real email if in test mode
    if app.config.get('MAIL_SUPPRESS_SEND'):
        return
        
    msg = Message('Password Reset Request - SpamGuard',
                 recipients=[user.email])
    msg.body = f'''Click to reset your password: {reset_url}'''
    mail.send(msg)

def generate_password_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset')

def verify_password_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt='password-reset',
            max_age=expiration
        )
    except:
        return None
    return email

def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')

def verify_verification_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return None
    return email


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get('username')
        if not username:
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        if not user or user.role != 'admin':
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route("/")
def home():
    if 'username' in session:
        return redirect(url_for('index'))
    return redirect(url_for('login'))

'''@app.route("/index")
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("index.html", username=session['username'])'''
@app.route("/index")
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("index.html", 
                         username=session['username'],
                         User=User)  # Pass User model to template

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            if not user.email_verified:
                flash('Please verify your email before logging in', 'error')
            else:
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template("login.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            new_user = User(
                username=username,
                email=email,
                password=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()
            
            send_verification_email(new_user)
            
            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
    
    return render_template("register.html")

@app.route('/verify-email/<token>')
def verify_email(token):
    email = verify_verification_token(token)
    if email is None:
        flash('The verification link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    if user.email_verified:
        flash('Account already verified. Please login.', 'info')
    else:
        user.email_verified = True
        db.session.commit()
        flash('Email verified successfully! You can now login.', 'success')
    
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(user)
            flash('Password reset instructions have been sent to your email.', 'info')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address.', 'error')
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_password_reset_token(token)
    if email is None:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            user = User.query.filter_by(email=email).first()
            user.password = generate_password_hash(password)
            db.session.commit()
            flash('Your password has been updated! You can now login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route("/logout")
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route("/admin")
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route("/about")
def about():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("about.html", username=session['username'])

@app.route("/contact")
def contact():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("contact.html", username=session['username'])

@app.route('/submit-contact', methods=['POST'])
def submit_contact():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        new_message = ContactMessage(
            name=data['name'],
            email=data['email'],
            message=data['message']
        )
        db.session.add(new_message)
        db.session.commit()
        
        # Optional: Send email notification to admin
        if not app.config.get('MAIL_SUPPRESS_SEND'):
            admin_email = os.getenv('ADMIN_EMAIL', 'admin@spamguard.com')
            msg = Message('New Contact Form Submission',
                         recipients=[admin_email])
            msg.body = f'''New message from {data['name']} ({data['email']}):
            
            {data['message']}
            '''
            mail.send(msg)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    
@app.route("/admin/messages")
@admin_required
def admin_messages():
    messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()
    return render_template('admin_messages.html', messages=messages, username=session['username'])

@app.route("/mark-read/<int:message_id>", methods=['POST'])
@admin_required
def mark_message_read(message_id):
    message = ContactMessage.query.get_or_404(message_id)
    message.is_read = True
    db.session.commit()
    return redirect(url_for('admin_messages'))

@app.route('/admin/edit-user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        user.email_verified = 'email_verified' in request.form
        
        # Only update password if a new one was provided
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
        
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('edit_user.html', user=user, username=session['username'])

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route("/privacy")
def privacy():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("privacy.html", username=session['username'])

@app.route("/terms")
def terms():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("terms.html", username=session['username'])

@app.route("/faq")
def faq():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("faq.html", username=session['username'])

@app.route("/predict", methods=["POST"])
def predict():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    email_text = request.form["email_text"]
    email_text = preprocess_text(email_text)

    sequence = tokenizer.texts_to_sequences([email_text])
    padded_sequence = pad_sequences(sequence, maxlen=max_length, padding="post")

    prediction = model.predict(padded_sequence)
    spam_probability = float(prediction[0][0])

    result = "Spam" if spam_probability > 0.7 else "Not Spam"
    return jsonify({"prediction": result, "probability": spam_probability})

if __name__ == "__main__":
    app.run(debug=True)