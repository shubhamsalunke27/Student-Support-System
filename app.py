from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3
import os
from datetime import datetime, timedelta
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time
import re
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure random key


# File upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

# Database configuration
app.config['DATABASE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')

# JWT configuration
app.config['JWT_SECRET_KEY'] = os.urandom(24)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')

# Initialize extensions
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Thread-local storage for database connections
_local = threading.local()

def get_db():
    if not hasattr(_local, 'db'):
        _local.db = sqlite3.connect(app.config['DATABASE'])
        _local.db.row_factory = sqlite3.Row
    return _local.db

class DatabaseContext:
    def __enter__(self):
        self.db = get_db()
        return self.db
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.db.rollback()
        else:
            self.db.commit()

def init_db():
    try:
        with app.app_context():
            # Create database directory if it doesn't exist
            os.makedirs(os.path.dirname(app.config['DATABASE']), exist_ok=True)
            
            # Create uploads directory
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            with DatabaseContext() as db:
                with open('schema.sql', 'r') as f:
                    db.executescript(f.read())
                
                # Create initial system admin if it doesn't exist
                admin_exists = db.execute('SELECT 1 FROM users WHERE role = "system_admin" LIMIT 1').fetchone()
                if not admin_exists:
                    db.execute(
                        'INSERT INTO users (username, password, role, full_name, email) '
                        'VALUES (?, ?, ?, ?, ?)',
                        ('admin', generate_password_hash('admin123'), 'system_admin', 'System Admin', 'admin@example.com')
                    )
                    print("Initial system admin account created:")
                    print("Username: admin")
                    print("Password: admin123")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        raise

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') not in ['admin', 'system_admin']:
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def system_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'system_admin':
            flash('System admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'student':
            flash('Student access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Helper functions
def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def create_notification(user_id, title, message, link=None):
    db = get_db()
    try:
        db.execute(
            'INSERT INTO notifications (user_id, title, message, link) VALUES (?, ?, ?, ?)',
            (user_id, title, message, link)
        )
        db.commit()
        
        # Get user email for notification
        user = db.execute('SELECT email FROM users WHERE id = ?', (user_id,)).fetchone()
        if user:
            # Send email notification in background
            threading.Thread(
                target=send_email,
                args=(user['email'], title, message)
            ).start()
    except sqlite3.Error as e:
        print(f"Error creating notification: {str(e)}")
    finally:
        db.close()

def check_and_escalate_complaints():
    """Check for complaints that need to be escalated (not resolved within 7 days)"""
    db = get_db()
    try:
        # Get complaints that are not resolved and have been pending for more than 7 days
        seven_days_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
        complaints = db.execute('''
            SELECT c.*, u.admin_level, u.admin_position 
            FROM complaints c
            LEFT JOIN users u ON c.admin_id = u.id
            WHERE c.status != 'resolved' 
            AND c.updated_at < ?
            AND c.status != 'escalated'
        ''', (seven_days_ago,)).fetchall()
        
        for complaint in complaints:
            # Get the escalation chain for this complaint category
            escalation_chain = db.execute('''
                SELECT * FROM escalation_chain 
                WHERE category = ? 
                ORDER BY position_level
            ''', (complaint['category'],)).fetchall()
            
            if not escalation_chain:
                continue
                
            # Find the next admin in the escalation chain
            current_level = complaint['escalation_level']
            next_level = current_level + 1
            
            if next_level >= len(escalation_chain):
                # Already at the highest level, mark as escalated
                db.execute('''
                    UPDATE complaints 
                    SET status = 'escalated', 
                        updated_at = CURRENT_TIMESTAMP,
                        last_escalation = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (complaint['id'],))
                
                # Notify the student
                create_notification(
                    complaint['student_id'],
                    'Complaint Escalated',
                    f'Your complaint #{complaint["id"]} has been escalated as it was not resolved within the expected time.',
                    url_for('view_complaint', complaint_id=complaint['id'])
                )
            else:
                # Find the next admin in the chain
                next_position = escalation_chain[next_level]['position_name']
                next_admin = db.execute('''
                    SELECT id FROM users 
                    WHERE admin_position = ? 
                    AND role = 'admin'
                    LIMIT 1
                ''', (next_position,)).fetchone()
                
                if next_admin:
                    # Update the complaint with the new admin
                    db.execute('''
                        UPDATE complaints 
                        SET admin_id = ?, 
                            updated_at = CURRENT_TIMESTAMP,
                            last_escalation = CURRENT_TIMESTAMP,
                            escalation_level = ?
                        WHERE id = ?
                    ''', (next_admin['id'], next_level, complaint['id']))
                    
                    # Notify the new admin
                    create_notification(
                        next_admin['id'],
                        'Complaint Escalated to You',
                        f'A complaint has been escalated to you. Please review and take action.',
                        url_for('admin_view_complaint', complaint_id=complaint['id'])
                    )
                    
                    # Notify the student
                    create_notification(
                        complaint['student_id'],
                        'Complaint Escalated',
                        f'Your complaint #{complaint["id"]} has been escalated to a higher authority.',
                        url_for('view_complaint', complaint_id=complaint['id'])
                    )
        
        db.commit()
    except sqlite3.Error as e:
        print(f"Error escalating complaints: {str(e)}")
        db.rollback()
    finally:
        db.close()

# Background task to check for complaints that need escalation
def run_escalation_check():
    while True:
        check_and_escalate_complaints()
        # Check every hour
        time.sleep(3600)

# Start the background thread for escalation checks
escalation_thread = threading.Thread(target=run_escalation_check, daemon=True)
escalation_thread.start()

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        if session['role'] == 'system_admin':
            return redirect(url_for('system_admin_dashboard'))
        elif session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('login'))
        
        try:
            with DatabaseContext() as db:
                user = db.execute(
                    'SELECT * FROM users WHERE username = ?', 
                    (username,)
                ).fetchone()
                
                if user and check_password_hash(user['password'], password):
                    if user['role'] == 'pending_admin':
                        flash('Your admin account is pending approval', 'info')
                        return redirect(url_for('login'))
                    
                    session.clear()
                    session.update({
                        'user_id': user['id'],
                        'username': user['username'],
                        'role': user['role'],
                        'full_name': user['full_name'],
                        'admin_level': user['admin_level'],
                        'admin_position': user['admin_position']
                    })
                    
                    # Create JWT token for API access
                    access_token = create_access_token(identity=user['id'])
                    session['access_token'] = access_token
                    
                    flash(f'Welcome back, {user["full_name"]}!', 'success')
                    return redirect(url_for('home'))
                
                flash('Invalid username or password', 'danger')
        except Exception as e:
            flash('An error occurred during login', 'danger')
            print(f"Login error: {str(e)}")
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        
        if not all([username, password, full_name, email]):
            flash('All required fields must be filled', 'danger')
            return redirect(url_for('register'))
        
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, password, role, full_name, email, phone) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (username, generate_password_hash(password), 'student', full_name, email, phone)
            )
            db.commit()
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        except sqlite3.Error as e:
            flash(f'Database error occurred: {str(e)}', 'danger')
        finally:
            db.close()
    
    return render_template('auth/register.html')

@app.route('/register/admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        admin_level = request.form.get('admin_level', '').strip()
        admin_position = request.form.get('admin_position', '').strip()
        
        if not all([username, password, full_name, email, admin_level, admin_position]):
            flash('All fields are required', 'danger')
            return redirect(url_for('register_admin'))
        
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, password, role, admin_level, admin_position, full_name, email, phone) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (username, generate_password_hash(password), 'pending_admin', admin_level, admin_position, full_name, email, phone)
            )
            db.commit()
            
            # Notify system admin about new admin request
            system_admins = db.execute('SELECT id FROM users WHERE role = "system_admin"').fetchall()
            for admin in system_admins:
                create_notification(
                    admin['id'],
                    'New Admin Registration Request',
                    f'A new admin registration request has been submitted by {full_name}.',
                    url_for('admin_approvals')
                )
            
            flash('Admin registration request submitted. Please wait for approval.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        except sqlite3.Error as e:
            flash(f'Database error occurred: {str(e)}', 'danger')
        finally:
            db.close()
    
    # Get available admin positions for the form
    db = get_db()
    try:
        admin_levels = ['academic', 'hostel', 'facilities', 'administration']
        admin_positions = db.execute('SELECT DISTINCT position_name FROM escalation_chain').fetchall()
        admin_positions = [pos['position_name'] for pos in admin_positions]
        return render_template('auth/register_admin.html', admin_levels=admin_levels, admin_positions=admin_positions)
    except sqlite3.Error as e:
        flash(f'Error retrieving admin positions: {str(e)}', 'danger')
        return redirect(url_for('login'))
    finally:
        db.close()

@app.route('/admin/approvals')
@admin_required
def admin_approvals():
    if session['role'] != 'system_admin':  # Only system admin can access
        flash('Only system admin can access this page', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    try:
        pending_admins = db.execute(
            'SELECT * FROM users WHERE role = "pending_admin"'
        ).fetchall()
        return render_template('admin/approvals.html', pending_admins=pending_admins)
    except sqlite3.Error as e:
        flash('Error retrieving pending admins', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        db.close()

@app.route('/admin/approve/<int:user_id>')
@admin_required
def approve_admin(user_id):
    if session['role'] != 'system_admin':  # Only system admin can approve
        flash('Only system admin can approve admins', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    try:
        # Get user details
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_approvals'))
        
        # Update user role to admin
        db.execute(
            'UPDATE users SET role = "admin" WHERE id = ?',
            (user_id,)
        )
        db.commit()
        
        # Notify the user
        create_notification(
            user_id,
            'Admin Approval',
            'Your admin account has been approved. You can now log in as an admin.',
            url_for('login')
        )
        
        # Send email notification
        send_email(
            user['email'],
            'Admin Account Approved',
            f'Dear {user["full_name"]},\n\nYour admin account has been approved. You can now log in to the system as an admin.\n\nBest regards,\nStudent Support System'
        )
        
        flash('User approved as admin', 'success')
    except sqlite3.Error as e:
        flash(f'Error approving admin: {str(e)}', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_approvals'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

# Student routes
@app.route('/student/dashboard')
@student_required
def student_dashboard():
    db = get_db()
    try:
        # Get user's complaints
        complaints = db.execute('''
            SELECT c.*, u.full_name as admin_name 
            FROM complaints c
            LEFT JOIN users u ON c.admin_id = u.id
            WHERE c.student_id = ?
            ORDER BY 
                CASE c.status 
                    WHEN 'pending' THEN 1
                    WHEN 'in_progress' THEN 2
                    WHEN 'resolved' THEN 3
                    WHEN 'escalated' THEN 4
                END,
                c.created_at DESC
        ''', (session['user_id'],)).fetchall()
        
        # Get unread notifications
        notifications = db.execute('''
            SELECT * FROM notifications 
            WHERE user_id = ? AND is_read = 0
            ORDER BY created_at DESC
            LIMIT 5
        ''', (session['user_id'],)).fetchall()
        
        # Get unread messages
        messages = db.execute('''
            SELECT m.*, u.full_name as sender_name 
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.receiver_id = ? AND m.is_read = 0
            ORDER BY m.created_at DESC
            LIMIT 5
        ''', (session['user_id'],)).fetchall()
        
        return render_template(
            'student/dashboard.html', 
            complaints=complaints,
            notifications=notifications,
            messages=messages
        )
    except sqlite3.Error as e:
        flash(f'Error retrieving dashboard data: {str(e)}', 'danger')
        return redirect(url_for('home'))
    finally:
        db.close()

@app.route('/student/complaint/new', methods=['GET', 'POST'])
@student_required
def new_complaint():
    if request.method == 'POST':
        category = request.form.get('category', '').strip()
        subcategory = request.form.get('subcategory', '').strip()
        description = request.form.get('description', '').strip()
        is_public = request.form.get('is_public') == 'on'
        priority = request.form.get('priority', 'normal')
        
        if not all([category, subcategory, description]):
            flash('All required fields must be filled', 'danger')
            return redirect(url_for('new_complaint'))
        
        file_path = None
        if 'file' in request.files:
            file = request.files['file']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.now().timestamp()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                file_path = filename
        
        db = get_db()
        try:
            # Find the appropriate admin based on category and escalation chain
            escalation_chain = db.execute('''
                SELECT * FROM escalation_chain 
                WHERE category = ? 
                ORDER BY position_level
                LIMIT 1
            ''', (category,)).fetchall()
            
            admin_id = None
            if escalation_chain:
                position = escalation_chain[0]['position_name']
                admin = db.execute('''
                    SELECT id FROM users 
                    WHERE admin_position = ? 
                    AND role = 'admin'
                    LIMIT 1
                ''', (position,)).fetchone()
                
                if admin:
                    admin_id = admin['id']
            
            # Insert the complaint using cursor
            cursor = db.cursor()
            cursor.execute('''
                INSERT INTO complaints (
                    student_id, admin_id, category, subcategory, description, 
                    file_path, is_public, priority
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session['user_id'], admin_id, category, subcategory, description, 
                file_path, is_public, priority
            ))
            
            complaint_id = cursor.lastrowid
            db.commit()
            
            # If admin is assigned, notify them
            if admin_id:
                create_notification(
                    admin_id,
                    'New Complaint Assigned',
                    f'A new complaint has been assigned to you. Please review and take action.',
                    url_for('admin_view_complaint', complaint_id=complaint_id)
                )
            
            flash('Complaint submitted successfully', 'success')
            return redirect(url_for('student_dashboard'))
        except sqlite3.Error as e:
            flash(f'Error submitting complaint: {str(e)}', 'danger')
        finally:
            db.close()
    
    return render_template('student/complaint.html', mode='new')

@app.route('/student/complaint/<int:complaint_id>')
@student_required
def view_complaint(complaint_id):
    db = get_db()
    try:
        # Get complaint details
        complaint = db.execute('''
            SELECT c.*, u.full_name as admin_name, u.admin_position 
            FROM complaints c
            LEFT JOIN users u ON c.admin_id = u.id
            WHERE c.id = ? AND c.student_id = ?
        ''', (complaint_id, session['user_id'])).fetchone()
        
        if not complaint:
            flash('Complaint not found', 'danger')
            return redirect(url_for('student_dashboard'))
        
        # Get feedback
        feedback = db.execute('''
            SELECT f.*, u.full_name as admin_name, u.admin_position 
            FROM feedback f
            JOIN users u ON f.admin_id = u.id
            WHERE f.complaint_id = ?
            ORDER BY f.created_at DESC
        ''', (complaint_id,)).fetchall()
        
        # Get messages
        messages = db.execute('''
            SELECT m.*, u.full_name as sender_name, u.role as sender_role
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.complaint_id = ? AND (m.sender_id = ? OR m.receiver_id = ?)
            ORDER BY m.created_at ASC
        ''', (complaint_id, session['user_id'], session['user_id'])).fetchall()
        
        # Mark messages as read
        db.execute('''
            UPDATE messages 
            SET is_read = 1 
            WHERE complaint_id = ? AND receiver_id = ? AND is_read = 0
        ''', (complaint_id, session['user_id']))
        
        db.commit()
        
        return render_template(
            'student/complaint.html', 
            complaint=complaint, 
            feedback=feedback,
            messages=messages,
            mode='view'
        )
    except sqlite3.Error as e:
        flash(f'Error retrieving complaint: {str(e)}', 'danger')
        return redirect(url_for('student_dashboard'))
    finally:
        db.close()

@app.route('/student/complaint/<int:complaint_id>/upvote', methods=['POST'])
@student_required
def upvote_complaint(complaint_id):
    db = get_db()
    try:
        # Check if complaint exists and is public
        complaint = db.execute('''
            SELECT * FROM complaints 
            WHERE id = ? AND is_public = 1
        ''', (complaint_id,)).fetchone()
        
        if not complaint:
            return jsonify({'success': False, 'message': 'Complaint not found or not public'}), 404
        
        # Check if user has already upvoted
        existing_upvote = db.execute('''
            SELECT 1 FROM upvotes 
            WHERE complaint_id = ? AND user_id = ?
        ''', (complaint_id, session['user_id'])).fetchone()
        
        if existing_upvote:
            # Remove upvote
            db.execute('''
                DELETE FROM upvotes 
                WHERE complaint_id = ? AND user_id = ?
            ''', (complaint_id, session['user_id']))
            
            db.execute('''
                UPDATE complaints 
                SET upvotes = upvotes - 1 
                WHERE id = ?
            ''', (complaint_id,))
            
            action = 'removed'
        else:
            # Add upvote
            db.execute('''
                INSERT INTO upvotes (complaint_id, user_id) 
                VALUES (?, ?)
            ''', (complaint_id, session['user_id']))
            
            db.execute('''
                UPDATE complaints 
                SET upvotes = upvotes + 1 
                WHERE id = ?
            ''', (complaint_id,))
            
            action = 'added'
        
        db.commit()
        
        # Get updated upvote count
        updated_complaint = db.execute('''
            SELECT upvotes FROM complaints 
            WHERE id = ?
        ''', (complaint_id,)).fetchone()
        
        return jsonify({
            'success': True, 
            'action': action, 
            'upvotes': updated_complaint['upvotes']
        })
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/student/complaint/<int:complaint_id>/message', methods=['POST'])
@student_required
def send_message(complaint_id):
    message = request.form.get('message', '').strip()
    
    if not message:
        flash('Message cannot be empty', 'danger')
        return redirect(url_for('view_complaint', complaint_id=complaint_id))
    
    db = get_db()
    try:
        # Check if complaint exists and belongs to the student
        complaint = db.execute('''
            SELECT * FROM complaints 
            WHERE id = ? AND student_id = ?
        ''', (complaint_id, session['user_id'])).fetchone()
        
        if not complaint:
            flash('Complaint not found', 'danger')
            return redirect(url_for('student_dashboard'))
        
        # Get the admin assigned to the complaint
        admin = db.execute('''
            SELECT id FROM users 
            WHERE id = ? AND role = 'admin'
        ''', (complaint['admin_id'],)).fetchone()
        
        if not admin:
            flash('No admin assigned to this complaint', 'danger')
            return redirect(url_for('view_complaint', complaint_id=complaint_id))
        
        # Insert the message
        db.execute('''
            INSERT INTO messages (sender_id, receiver_id, complaint_id, message) 
            VALUES (?, ?, ?, ?)
        ''', (session['user_id'], admin['id'], complaint_id, message))
        
        db.commit()
        
        # Notify the admin
        create_notification(
            admin['id'],
            'New Message',
            f'You have received a new message regarding complaint #{complaint_id}.',
            url_for('admin_view_complaint', complaint_id=complaint_id)
        )
        
        # Emit socket event for real-time updates
        socketio.emit('new_message', {
            'complaint_id': complaint_id,
            'sender_id': session['user_id'],
            'sender_name': session['full_name'],
            'message': message,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }, room=f'complaint_{complaint_id}')
        
        flash('Message sent successfully', 'success')
    except sqlite3.Error as e:
        flash(f'Error sending message: {str(e)}', 'danger')
    finally:
        db.close()
    
    return redirect(url_for('view_complaint', complaint_id=complaint_id))

# Admin routes
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    try:
        # Get assigned complaints
        complaints = db.execute('''
            SELECT c.*, u.full_name as student_name 
            FROM complaints c
            JOIN users u ON c.student_id = u.id
            WHERE c.admin_id = ?
            ORDER BY 
                CASE c.status 
                    WHEN 'pending' THEN 1
                    WHEN 'in_progress' THEN 2
                    WHEN 'resolved' THEN 3
                    WHEN 'escalated' THEN 4
                END,
                CASE c.priority
                    WHEN 'urgent' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'normal' THEN 3
                    WHEN 'low' THEN 4
                END,
                c.created_at DESC
        ''', (session['user_id'],)).fetchall()
        
        # Get unread notifications
        notifications = db.execute('''
            SELECT * FROM notifications 
            WHERE user_id = ? AND is_read = 0
            ORDER BY created_at DESC
            LIMIT 5
        ''', (session['user_id'],)).fetchall()
        
        # Get unread messages
        messages = db.execute('''
            SELECT m.*, u.full_name as sender_name 
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.receiver_id = ? AND m.is_read = 0
            ORDER BY m.created_at DESC
            LIMIT 5
        ''', (session['user_id'],)).fetchall()
        
        # Get pending admin approvals count (for system admin)
        pending_admins_count = 0
        if session['role'] == 'system_admin':
            pending_admins_count = db.execute('''
                SELECT COUNT(*) as count 
                FROM users 
                WHERE role = 'pending_admin'
            ''').fetchone()['count']
        
        return render_template(
            'admin/dashboard.html', 
            complaints=complaints,
            notifications=notifications,
            messages=messages,
            pending_admins_count=pending_admins_count
        )
    except sqlite3.Error as e:
        flash(f'Error retrieving dashboard data: {str(e)}', 'danger')
        return redirect(url_for('home'))
    finally:
        db.close()

@app.route('/admin/complaint/<int:complaint_id>', methods=['GET', 'POST'])
@admin_required
def admin_view_complaint(complaint_id):
    db = get_db()
    try:
        # Get complaint details
        complaint = db.execute('''
            SELECT c.*, u.full_name as student_name, u.email as student_email 
            FROM complaints c
            JOIN users u ON c.student_id = u.id
            WHERE c.id = ? AND c.admin_id = ?
        ''', (complaint_id, session['user_id'])).fetchone()
        
        if not complaint:
            flash('Complaint not found or not assigned to you', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        if request.method == 'POST':
            status = request.form.get('status')
            feedback_msg = request.form.get('feedback', '').strip()
            priority = request.form.get('priority', complaint['priority'])
            
            if status not in ['pending', 'in_progress', 'resolved']:
                flash('Invalid status', 'danger')
                return redirect(url_for('admin_view_complaint', complaint_id=complaint_id))
            
            try:
                # Update complaint status
                db.execute('''
                    UPDATE complaints 
                    SET status = ?, 
                        updated_at = CURRENT_TIMESTAMP,
                        priority = ?
                    WHERE id = ?
                ''', (status, priority, complaint_id))
                
                # Add feedback if provided
                if feedback_msg:
                    db.execute('''
                        INSERT INTO feedback (complaint_id, admin_id, message) 
                        VALUES (?, ?, ?)
                    ''', (complaint_id, session['user_id'], feedback_msg))
                
                db.commit()
                
                # Notify the student
                create_notification(
                    complaint['student_id'],
                    'Complaint Updated',
                    f'Your complaint #{complaint_id} has been updated to "{status.replace("_", " ").title()}".',
                    url_for('view_complaint', complaint_id=complaint_id)
                )
                
                # Send email notification
                send_email(
                    complaint['student_email'],
                    f'Complaint #{complaint_id} Updated',
                    f'Dear Student,\n\nYour complaint has been updated to "{status.replace("_", " ").title()}".\n\nBest regards,\nStudent Support System'
                )
                
                flash('Complaint updated successfully', 'success')
            except sqlite3.Error as e:
                flash(f'Error updating complaint: {str(e)}', 'danger')
            
            return redirect(url_for('admin_view_complaint', complaint_id=complaint_id))
        
        # Get feedback history
        feedback = db.execute('''
            SELECT f.*, u.full_name as admin_name, u.admin_position 
            FROM feedback f
            JOIN users u ON f.admin_id = u.id
            WHERE f.complaint_id = ?
            ORDER BY f.created_at DESC
        ''', (complaint_id,)).fetchall()
        
        # Get messages
        messages = db.execute('''
            SELECT m.*, u.full_name as sender_name, u.role as sender_role
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.complaint_id = ? AND (m.sender_id = ? OR m.receiver_id = ?)
            ORDER BY m.created_at ASC
        ''', (complaint_id, session['user_id'], session['user_id'])).fetchall()
        
        # Mark messages as read
        db.execute('''
            UPDATE messages 
            SET is_read = 1 
            WHERE complaint_id = ? AND receiver_id = ? AND is_read = 0
        ''', (complaint_id, session['user_id']))
        
        db.commit()
        
        return render_template(
            'admin/complaint.html', 
            complaint=complaint, 
            feedback=feedback,
            messages=messages
        )
    except sqlite3.Error as e:
        flash(f'Error retrieving complaint: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        db.close()

@app.route('/admin/complaint/<int:complaint_id>/message', methods=['POST'])
@admin_required
def admin_send_message(complaint_id):
    message = request.form.get('message', '').strip()
    
    if not message:
        flash('Message cannot be empty', 'danger')
        return redirect(url_for('admin_view_complaint', complaint_id=complaint_id))
    
    db = get_db()
    try:
        # Check if complaint exists and is assigned to the admin
        complaint = db.execute('''
            SELECT * FROM complaints 
            WHERE id = ? AND admin_id = ?
        ''', (complaint_id, session['user_id'])).fetchone()
        
        if not complaint:
            flash('Complaint not found or not assigned to you', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        # Insert the message
        db.execute('''
            INSERT INTO messages (sender_id, receiver_id, complaint_id, message) 
            VALUES (?, ?, ?, ?)
        ''', (session['user_id'], complaint['student_id'], complaint_id, message))
        
        db.commit()
        
        # Notify the student
        create_notification(
            complaint['student_id'],
            'New Message',
            f'You have received a new message regarding your complaint #{complaint_id}.',
            url_for('view_complaint', complaint_id=complaint_id)
        )
        
        # Emit socket event for real-time updates
        socketio.emit('new_message', {
            'complaint_id': complaint_id,
            'sender_id': session['user_id'],
            'sender_name': session['full_name'],
            'message': message,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }, room=f'complaint_{complaint_id}')
        
        flash('Message sent successfully', 'success')
    except sqlite3.Error as e:
        flash(f'Error sending message: {str(e)}', 'danger')
    finally:
        db.close()
    
    return redirect(url_for('admin_view_complaint', complaint_id=complaint_id))

# System Admin routes
@app.route('/system-admin/dashboard')
@system_admin_required
def system_admin_dashboard():
    db = get_db()
    try:
        # Get all complaints for analytics
        all_complaints = db.execute('''
            SELECT c.*, u.full_name as student_name, a.full_name as admin_name
            FROM complaints c
            JOIN users u ON c.student_id = u.id
            LEFT JOIN users a ON c.admin_id = a.id
            ORDER BY c.created_at DESC
            LIMIT 50
        ''').fetchall()
        
        # Get complaint statistics
        stats = db.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved,
                SUM(CASE WHEN status = 'escalated' THEN 1 ELSE 0 END) as escalated
            FROM complaints
        ''').fetchone()
        
        # Get category statistics
        categories = db.execute('''
            SELECT category, COUNT(*) as count
            FROM complaints
            GROUP BY category
            ORDER BY count DESC
        ''').fetchall()
        
        # Get admin performance
        admin_performance = db.execute('''
            SELECT 
                u.full_name,
                u.admin_position,
                COUNT(c.id) as total_complaints,
                SUM(CASE WHEN c.status = 'resolved' THEN 1 ELSE 0 END) as resolved_complaints,
                AVG(CASE 
                    WHEN c.status = 'resolved' 
                    THEN (julianday(c.updated_at) - julianday(c.created_at))
                    ELSE NULL 
                END) as avg_resolution_time
            FROM users u
            LEFT JOIN complaints c ON u.id = c.admin_id
            WHERE u.role = 'admin'
            GROUP BY u.id
            ORDER BY total_complaints DESC
        ''').fetchall()
        
        # Get unread notifications
        notifications = db.execute('''
            SELECT * FROM notifications 
            WHERE user_id = ? AND is_read = 0
            ORDER BY created_at DESC
            LIMIT 5
        ''', (session['user_id'],)).fetchall()

        # Get pending admin requests count
        pending_admins_count = db.execute('''
            SELECT COUNT(*) as count 
            FROM users 
            WHERE role = 'pending_admin'
        ''').fetchone()['count']
        
        return render_template(
            'admin/system_dashboard.html', 
            complaints=all_complaints,
            stats=stats,
            categories=categories,
            admin_performance=admin_performance,
            notifications=notifications,
            pending_admins_count=pending_admins_count
        )
    except sqlite3.Error as e:
        flash(f'Error retrieving dashboard data: {str(e)}', 'danger')
        return redirect(url_for('home'))
    finally:
        db.close()

@app.route('/system-admin/users')
@system_admin_required
def manage_users():
    db = get_db()
    try:
        users = db.execute('''
            SELECT * FROM users
            ORDER BY role, created_at DESC
        ''').fetchall()
        
        return render_template('admin/users.html', users=users)
    except sqlite3.Error as e:
        flash(f'Error retrieving users: {str(e)}', 'danger')
        return redirect(url_for('system_admin_dashboard'))
    finally:
        db.close()

@app.route('/system-admin/user/<int:user_id>/delete', methods=['POST'])
@system_admin_required
def delete_user(user_id):
    db = get_db()
    try:
        # Check if user exists
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('manage_users'))
        
        # Don't allow deleting the current user
        if user_id == session['user_id']:
            flash('You cannot delete your own account', 'danger')
            return redirect(url_for('manage_users'))
        
        # Delete user
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
        
        flash(f'User {user["full_name"]} has been deleted', 'success')
    except sqlite3.Error as e:
        flash(f'Error deleting user: {str(e)}', 'danger')
    finally:
        db.close()
    
    return redirect(url_for('manage_users'))

# API routes for real-time updates
@app.route('/api/notifications')
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()
    
    db = get_db()
    try:
        notifications = db.execute('''
            SELECT * FROM notifications 
            WHERE user_id = ? AND is_read = 0
            ORDER BY created_at DESC
        ''', (user_id,)).fetchall()
        
        # Mark notifications as read
        db.execute('''
            UPDATE notifications 
            SET is_read = 1 
            WHERE user_id = ? AND is_read = 0
        ''', (user_id,))
        
        db.commit()
        
        return jsonify([dict(notification) for notification in notifications])
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()

# Socket.IO events
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)

@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)

# File download route
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    # Create upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize database
    with app.app_context():
        init_db()
        
    # Run the app with SocketIO

    socketio.run(app, debug=True)
