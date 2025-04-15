# SpamGuard - AI-Powered Email Classifier
🚀 SpamGuard is a Flask-based web application that uses deep learning (TensorFlow/Keras) to classify emails as spam or not spam with high accuracy. It features user authentication, email verification, password recovery, and an admin dashboard for user management.

# ✨ Key Features
✅ AI Email Classification – Uses a pre-trained neural network to detect spam emails
✅ User Authentication – Secure login/registration with password hashing
✅ Email Verification – Users must verify their email before accessing the system
✅ Password Recovery – Secure token-based password reset via email
✅ Admin Dashboard – Manage users, view messages, and monitor activity
✅ Responsive UI – Clean and intuitive interface for seamless user experience

# 🛠️ Tech Stack
Backend: Python, Flask, SQLAlchemy

AI/ML: TensorFlow, Keras, NLTK (for text preprocessing)

Database: SQLite (with Flask-SQLAlchemy)

Authentication: Werkzeug Security, Flask-Mail for email verification

Frontend: HTML, CSS, JavaScript (with Jinja2 templating)

# 📌 How It Works
Preprocessing: Emails are cleaned (lowercase, stopwords removed, hyperlinks stripped)

# 🚀 Getting Started
Clone the repo:

```bash
git clone https://github.com/yourusername/SpamGuard.git
cd SpamGuard
```
Install dependencies:

```bash
pip install -r requirements.txt
```
Run the Flask app:

```bash
python app.py
```
Access the app at http://localhost:5000

# 📸 Screenshots

Tokenization: Text is converted to sequences using a trained tokenizer

Prediction: A deep learning model evaluates the email and returns a spam probability score

Result: Classified as "Spam" (if probability > 70%) or "Not Spam"


### Login Page  
![Login Page](/login.png)  

### Email Classification Demo  
![Prediction Demo](/Spam_Classifier.png)  

### Admin Dashboard  
![Admin Panel](/admin.png)

