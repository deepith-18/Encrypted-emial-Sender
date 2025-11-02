# app.py
import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from database.db_manager import get_db_connection, init_db
from crypto import key_manager, hybrid_cipher
from email_handler import smtp_sender, message_parser

# --- Flask App Setup ---
app = Flask(__name__)
app.config.from_object(Config)

# --- Database Initialization ---
if not os.path.exists(Config.DATABASE):
    with app.app_context():
        init_db()
        print("Database initialized.")

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "info"

class User(UserMixin):
    def __init__(self, id, username, email, password_hash, public_key_pem, private_key_encrypted):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.public_key_pem = public_key_pem
        self.private_key_encrypted = private_key_encrypted

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['email'], user_data['password_hash'], user_data['public_key_pem'], user_data['private_key_encrypted'])
    return None

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        if conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        
        private_key_pem, public_key_pem = key_manager.generate_rsa_keys()
        private_key_encrypted = key_manager.encrypt_private_key(private_key_pem, password)

        conn.execute('INSERT INTO users (username, email, password_hash, public_key_pem, private_key_encrypted) VALUES (?, ?, ?, ?, ?)',
                     (username, email, generate_password_hash(password), public_key_pem.decode(), private_key_encrypted))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], user_data['username'], user_data['email'], user_data['password_hash'], user_data['public_key_pem'], user_data['private_key_encrypted'])
            login_user(user)
            session['user_password'] = password
            return redirect(url_for('index'))
        
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_password', None)
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/compose')
@login_required
def compose():
    return render_template('compose.html')

@app.route('/compose_ajax', methods=['POST'])
@login_required
def compose_ajax():
    recipient_email = request.form['recipient_email']
    subject = request.form['subject']
    message = request.form['message']

    conn = get_db_connection()
    recipient_data = conn.execute('SELECT public_key_pem FROM users WHERE email = ?', (recipient_email,)).fetchone()
    conn.close()

    if not recipient_data:
        return jsonify({'success': False, 'message': 'Recipient not found in our system.'})

    recipient_public_key = recipient_data['public_key_pem']
    password = session.get('user_password')
    if not password:
        return jsonify({'success': False, 'message': 'Session expired. Please log in again.'})

    try:
        sender_private_key = key_manager.load_private_key_from_pem(current_user.private_key_encrypted, password)
    except ValueError:
        return jsonify({'success': False, 'message': 'Internal error: Could not decrypt your private key.'})

    encrypted_parts = hybrid_cipher.hybrid_encrypt(
        message.encode('utf-8'),
        recipient_public_key.encode('utf-8'),
        sender_private_key
    )
    
    email_body = smtp_sender.format_encrypted_body(encrypted_parts)
    success, status_msg = smtp_sender.send_email(recipient_email, subject, email_body)

    return jsonify({'success': success, 'message': status_msg})

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt_page():
    if request.method == 'POST':
        encrypted_message_body = request.form['encrypted_message']
        sender_email = request.form['sender_email']
        
        encrypted_data = message_parser.parse_encrypted_message(encrypted_message_body)
        if not encrypted_data:
            flash('Invalid encrypted message format.', 'danger')
            return redirect(url_for('decrypt_page'))

        conn = get_db_connection()
        sender_data = conn.execute('SELECT public_key_pem FROM users WHERE email = ?', (sender_email,)).fetchone()
        conn.close()

        if not sender_data:
            flash('Sender public key not found.', 'danger')
            return redirect(url_for('decrypt_page'))
        
        sender_public_key = sender_data['public_key_pem']
        password = session.get('user_password')
        try:
            recipient_private_key = key_manager.load_private_key_from_pem(current_user.private_key_encrypted, password)
        except ValueError:
            flash('Could not decrypt your private key. Wrong password in session?', 'danger')
            return redirect(url_for('login'))

        decrypted_message_bytes = hybrid_cipher.hybrid_decrypt(
            encrypted_data,
            recipient_private_key,
            sender_public_key.encode('utf-8')
        )

        if decrypted_message_bytes:
            decrypted_message = decrypted_message_bytes.decode('utf-8')
            return render_template('decrypt.html', decrypted_message=decrypted_message)
        else:
            flash('Decryption failed. The message may be corrupt or the signature invalid.', 'danger')

    return render_template('decrypt.html', decrypted_message=None)

@app.route('/keys')
@login_required
def keys():
    return render_template('keys.html', public_key=current_user.public_key_pem)

if __name__ == '__main__':
    app.run(debug=True)