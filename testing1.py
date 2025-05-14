from flask import Flask, render_template, request, jsonify, url_for, redirect, session, flash, abort
import numpy as np
import tensorflow as tf
from urllib.parse import quote_plus
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import string
import re
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os
from functools import wraps
from dotenv import load_dotenv
from datetime import datetime
#from flask_mongoengine import MongoEngine
from mongoengine import connect, Document, StringField, BooleanField, DateTimeField
from pymongo import MongoClient
import certifi

load_dotenv()

# 1. Define the NLTK data directory path
nltk_data_dir = os.path.join(os.path.dirname(__file__), 'nltk_data')

# 2. Set environment variable AND add to nltk's path
os.environ['NLTK_DATA'] = nltk_data_dir  # Force system-wide recognition
nltk.data.path.append(nltk_data_dir)     # Add to nltk's search path

# 3. Download required resources with fallback
required_resources = ['punkt', 'stopwords', 'popular']

for resource in required_resources:
    try:
        nltk.data.find(resource)
    except LookupError:
        nltk.download(resource, download_dir=nltk_data_dir)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

# MongoDB configuration
mongodb_user = quote_plus(os.getenv('MONGODB_USER', ''))
mongodb_pass = quote_plus(os.getenv('MONGODB_PASSWORD', ''))
mongodb_cluster = os.getenv('MONGODB_CLUSTER', '')
mongodb_db = 'spamguard'

app.config['MONGODB_URI'] = (
    f"mongodb+srv://{mongodb_user}:{mongodb_pass}@{mongodb_cluster}/"
    f"{mongodb_db}?retryWrites=true&w=majority"
    f"&tls=true&tlsCAFile={certifi.where()}"
)

try:
    client = MongoClient(
        app.config['MONGODB_URI'],
        tls=True,
        tlsCAFile=certifi.where(),
        connectTimeoutMS=30000,
        serverSelectionTimeoutMS=5000
    )
    print("✅ MongoDB Connected! Version:", client.server_info()['version'])
    connect(
        db=mongodb_db,
        host=app.config['MONGODB_URI'],
        tls=True,
        tlsCAFile=certifi.where(),
        connectTimeoutMS=30000,
        serverSelectionTimeoutMS=5000
    )
except Exception as e:
    print("❌ MongoDB Connection Failed:", e)
    raise RuntimeError("Database connection failed") from e
# Email configuration
# Replace your current email config with this:
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ssohamm12@gmail.com'  # Your Gmail address
app.config['MAIL_PASSWORD'] = 'hczf earth chyt dcgq'  # Generated app password (see below)
app.config['MAIL_DEFAULT_SENDER'] = 'ssohamm12@gmail.com'  # Your Gmail address
app.config['MAIL_SUPPRESS_SEND'] = True  # Actually send emails
mail = Mail(app)



# User model
class User(Document):  # Notice Document instead of db.Document
    username = StringField(unique=True, required=True)
    email = StringField(unique=True, required=True)
    password = StringField(required=True)
    email_verified = BooleanField(default=False)
    created_at = DateTimeField(default=datetime.utcnow)
    role = StringField(default='user')
    
    meta = {
        'collection': 'users',
        'indexes': [
            'username',
            'email'
        ]
    }

    
# Contact Message model
class ContactMessage(Document):
    name = StringField(required=True)
    email = StringField(required=True)
    message = StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)
    is_read = BooleanField(default=False)
    
    meta = {
        'collection': 'contact_messages',
        'indexes': [
            '-created_at',
            'email'
        ]
    }

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
    with open("model/tokenizer.pkl", "rb") as handle:
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


def send_verification_email(user):
    token = generate_verification_token(user.email)
    verify_url = url_for('verify_email', token=token, _external=True)
    
    # Print to terminal instead of sending an email
    print("\n" + "="*50)
    print(f"📧 Verification Email (Mock) for: {user.email}")
    print(f"🔗 Verification URL: {verify_url}")
    print("="*50 + "\n")

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

def send_password_reset_email(user):
    token = generate_password_reset_token(user.email)
    reset_url = url_for('reset_password', token=token, _external=True)
    
    # Debug print (for terminal testing)
    if app.debug:
        print("\n" + "="*50)
        print(f"🔑 Password Reset Link for: {user.email}")
        print(f"🔗 Reset URL: {reset_url}")
        print("="*50 + "\n")
    
    # Skip sending real email if in test mode
    if app.config.get('MAIL_SUPPRESS_SEND'):
        return
        
    msg = Message('Password Reset Request - SpamGuard',
                 recipients=[user.email])
    msg.body = f'''Click to reset your password: {reset_url}'''
    mail.send(msg)

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
        
        # MongoEngine query (replaces User.query.filter_by)
        user = User.objects(username=username).first()
        
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
    
    # MongoEngine query (replaces User.query.filter_by)
    user = User.objects(username=session['username']).first()
    
    return render_template("index.html", 
                         username=session['username'],
                         user=user)  # Pass User model to template

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.objects(username=username).first()  # MongoEngine style
        
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
        
        if User.objects(username=username).first():
            flash('Username already exists', 'error')
        elif User.objects(email=email).first():
            flash('Email already registered', 'error')
        else:
            new_user = User(username=username, email=email, password=generate_password_hash(password))
            new_user.save()
            
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
    
    # MongoEngine query (replaces User.query.filter_by)
    user = User.objects(email=email).first()
    
    if not user:
        flash('User not found.', 'error')
    elif user.email_verified:
        flash('Account already verified. Please login.', 'info')
    else:
        user.email_verified = True
        user.save()  # MongoEngine save() instead of db.session.commit()
        flash('Email verified successfully! You can now login.', 'success')
    
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        # MongoEngine query to find user
        user = User.objects(email=email).first()
        
        if user:
            send_password_reset_email(user)  # Call the function
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
            # MongoEngine query to find user
            user = User.objects(email=email).first()
            if user:
                user.password = generate_password_hash(password)
                user.save()  # MongoEngine's save() instead of db.session.commit()
                flash('Your password has been updated! You can now login.', 'success')
                return redirect(url_for('login'))
            else:
                flash('User not found', 'error')
    
    return render_template('reset_password.html', token=token)

@app.route("/logout")
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route("/admin")
@admin_required
def admin_dashboard():
    users = User.objects.all()  # Note: .all() returns a queryset
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
        ).save()
        
        # Email sending code remains the same
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    
@app.route("/admin/messages")
@admin_required
def admin_messages():
    messages = ContactMessage.objects.order_by('-created_at')
    return render_template('admin_messages.html', messages=messages, username=session['username'])

@app.route("/mark-read/<string:message_id>", methods=['POST'])
@admin_required
def mark_message_read(message_id):
    # 1) try to fetch (raises ContactMessage.DoesNotExist if not found)
    try:
        message = ContactMessage.objects.get(id=message_id)
    except ContactMessage.DoesNotExist:
        # if you want a Flask 404
        abort(404)
    except Exception as e:
        flash(f"Error fetching message: {e}", "error")
        return redirect(url_for("admin_messages"))

    # 2) now update
    try:
        message.update(set__is_read=True)
    except Exception as e:
        flash(f"Error marking message as read: {e}", "error")

    return redirect(url_for("admin_messages"))

@app.route('/admin/edit-user/<string:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    try:
        # Get user or return 404
        user = User.objects.get(id=user_id)
        
        if request.method == 'POST':
            user.username = request.form['username']
            user.email = request.form['email']
            user.role = request.form['role']
            user.email_verified = 'email_verified' in request.form
            
            if request.form['password']:
                user.password = generate_password_hash(request.form['password'])
            
            user.save()  # MongoEngine save operation
            flash('User updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        return render_template('edit_user.html', 
                            user=user,
                            username=session['username'])
    
    except User.DoesNotExist:
        abort(404)  # User not found
    except Exception as e:
        flash(f'Error updating user: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-user/<string:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    try:
        # Get user or raise 404
        user = User.objects.get(id=user_id)
        
        # Prevent admin from deleting themselves
        if user.username == session.get('username'):
            flash('You cannot delete your own account!', 'error')
            return redirect(url_for('admin_dashboard'))
            
        user.delete()
        flash('User deleted successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
        
    except User.DoesNotExist:
        abort(404, description="User not found")
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
        app.logger.error(f'Error deleting user {user_id}: {str(e)}')
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

handler = app

if __name__ == "__main__":
    app.run(debug=True)
#if __name__ == "__main__":
    #import os
    #port = int(os.environ.get("PORT", 5000))
    #app.run(host="0.0.0.0", port=port)
