import os
import uuid
import tempfile
import logging
import requests
import pymysql
import mysql.connector
import sqlalchemy
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from google.cloud import storage
from google.cloud.sql.connector import Connector
from dotenv import load_dotenv
from datetime import datetime, timedelta
from google.auth import compute_engine, default

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Constants
BUCKET_NAME = os.getenv('GCS_BUCKET_NAME', 'photogallerygcpbucket')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

# Initialize Google Cloud Storage
storage_client = storage.Client()
bucket = storage_client.bucket(BUCKET_NAME)

# Utility Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    """Creates a connection to the Cloud SQL database."""
    connector = Connector()
    
    conn = connector.connect(
        os.getenv("DB_CONNECTION_NAME"),       
        "pymysql",
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database='photogallery'
    )
    
    return conn

def generate_signed_url(blob_name, expiration=3600):
    """Generates a URL for a given blob in Google Cloud Storage."""
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(blob_name)
        
        # For App Engine environment, use a public URL approach
        if os.environ.get('GAE_ENV', ''):
            # Generate a public URL instead of a signed one
            return f"https://storage.googleapis.com/{BUCKET_NAME}/{blob_name}"
        else:
            # Use signed URL for non-App Engine environments
            return blob.generate_signed_url(
                version="v4",
                expiration=timedelta(seconds=expiration),
                method="GET"
            )
    except Exception as e:
        logger.error(f"Error generating URL: {str(e)}")
        # Fallback to public URL
        return f"https://storage.googleapis.com/{BUCKET_NAME}/{blob_name}"

# Authentication Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validate password confirmation
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        # Hash the password
        password_hash = generate_password_hash(password)
        
        db = None
        try:
            db = get_db_connection()
            cursor = db.cursor()
            
            # Insert new user
            cursor.execute(
                'INSERT INTO users (username, password_hash) VALUES (%s, %s)', 
                (username, password_hash)
            )
            db.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        
        except mysql.connector.IntegrityError:
            flash('Username already exists.', 'error')
        
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
        
        finally:
            if db:
                cursor.close()
                db.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db_connection()
        cursor = db.cursor(cursor=pymysql.cursors.DictCursor)        
        # Check user credentials
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        db.close()
        
        if user and check_password_hash(user['password_hash'], password):
            # Store user info in session
            session['user_id'] = user['id']
            session['username'] = user['username']
            
            flash('Login successful!', 'success')
            return redirect(url_for('gallery'))
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Navigation Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('gallery'))
    return redirect(url_for('login'))

# Photo Management Routes
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    # Check if user is logged in
    if 'user_id' not in session:
        flash('Please log in to upload photos.', 'error')
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('upload.html')

    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        files = request.files.getlist('photo')
        uploaded_files = []

        for file in files:
            if file.filename == '':
                continue  # Skip empty file selection

            if file and allowed_file(file.filename):
                original_filename = secure_filename(file.filename)
                unique_filename = f"{session['username']}/{uuid.uuid4()}_{original_filename}"

                try:
                    # Upload to Google Cloud Storage
                    storage_client = storage.Client()
                    bucket = storage_client.bucket(BUCKET_NAME)
                    blob = bucket.blob(unique_filename)
                    blob.upload_from_file(file, content_type=file.content_type)
                    
                    # Instead of using make_public(), just use the public URL format
                    photo_url = f"https://storage.googleapis.com/{BUCKET_NAME}/{unique_filename}"

                    # Store metadata in database
                    db = get_db_connection()
                    cursor = db.cursor(cursor=pymysql.cursors.DictCursor)  

                    cursor.execute(
                        'INSERT INTO photos (user_id, photo_url, original_filename) VALUES (%s, %s, %s)',
                        (session['user_id'], photo_url, original_filename)
                    )
                    db.commit()
                    db.close()

                    uploaded_files.append(original_filename)

                except Exception as e:
                    logger.error(f"Upload error: {str(e)}")
                    flash(f'Error uploading {original_filename}: {str(e)}', 'error')
            else:
                flash(f'Invalid file type for {file.filename}', 'error')

        if uploaded_files:
            flash(f'Uploaded {len(uploaded_files)} photo(s) successfully!', 'success')

        return redirect(url_for('gallery'))

    return render_template('upload.html')

@app.route('/gallery', methods=['GET'])
def gallery():
    if not session.get('user_id'):
        flash('Please log in to view your gallery.', 'error')
        return redirect(url_for('login'))
        
    db = get_db_connection()
    cursor = db.cursor(cursor=pymysql.cursors.DictCursor)  
    
    search_query = request.args.get('search', '')  # Get search term from query parameters
    user_id = session.get('user_id')

    if search_query:
        cursor.execute(
            "SELECT id, photo_url, original_filename FROM photos WHERE user_id = %s AND original_filename LIKE %s",
            (user_id, f"%{search_query}%")
        )
    else:
        cursor.execute(
            "SELECT id, photo_url, original_filename FROM photos WHERE user_id = %s", 
            (user_id,)
        )

    photos = cursor.fetchall()
    db.close()
    
    return render_template('gallery.html', photos=photos, search_query=search_query)

@app.route('/download/<int:photo_id>')
def download_photo(photo_id):
    temp_file_path = None
    
    if 'user_id' not in session:
        flash('Please log in to download photos.', 'error')
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(cursor=pymysql.cursors.DictCursor)

    cursor.execute("SELECT photo_url, original_filename FROM photos WHERE id = %s AND user_id = %s", 
                   (photo_id, session['user_id']))
    photo = cursor.fetchone()
    db.close()

    if not photo:
        flash("Photo not found or you don't have permission to download it.", "error")
        return redirect(url_for('gallery'))

    try:
        # Get the URL
        photo_url = photo['photo_url']

        # Download the file using requests
        response = requests.get(photo_url, stream=True)
        
        if response.status_code == 200:
            # Use a temporary file to store the downloaded content
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file_path = temp_file.name

            # Send the file for download
            return send_file(
                temp_file_path, 
                as_attachment=True, 
                download_name=photo['original_filename']
            )
        else:
            flash("Failed to download photo.", "error")
            return redirect(url_for('gallery'))

    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        flash(f"Error downloading photo: {str(e)}", "error")
        return redirect(url_for('gallery'))
    finally:
        # Clean up the temporary file if it exists
        if temp_file_path and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

# Main entry point
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))