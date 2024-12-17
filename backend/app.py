from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
from mysql.connector import errorcode
from werkzeug.security import generate_password_hash, check_password_hash
import re
import logging

# Initialize Flask App
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# Configure Logging
logging.basicConfig(level=logging.INFO)

# Database Configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'ecommerce_db'
}

# Utility function to validate email format
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

# Utility function to enforce password policy
def is_valid_password(password):
    # Must be at least 8 characters, include uppercase, number, and special character
    return len(password) >= 8 and re.search(r'[A-Z]', password) and re.search(r'\d', password) and re.search(r'[!@#$%^&*(),.?":{}|<>]', password)

# Route for User Signup
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        # Get JSON data from the request
        data = request.json
        username = data.get('username')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        date_of_birth = data.get('date_of_birth')
        gender = data.get('gender')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirmPassword')
        contact_number = data.get('contact_number')

        # Validate required fields
        if not all([username, first_name, last_name, date_of_birth, gender, email, password, confirm_password, contact_number]):
            return jsonify({'error': 'All fields are required'}), 400

        # Validate email format
        if not is_valid_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        # Validate password policy
        if not is_valid_password(password):
            return jsonify({'error': 'Password must be at least 8 characters long, include an uppercase letter, a number, and a special character'}), 400

        # Validate password matching
        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        # Hash the password using PBKDF2 with SHA256
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        # Connect to the database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Check if username or email already exists
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({'error': 'Username or email already exists'}), 409

        # Insert data into the users table
        insert_query = """
            INSERT INTO users (username, first_name, last_name, date_of_birth, gender, email, password, contact_number)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (username, first_name, last_name, date_of_birth, gender, email, password_hash, contact_number))
        conn.commit()

        # Close the connection
        cursor.close()
        conn.close()

        logging.info(f"User {username} registered successfully")
        return jsonify({'message': 'User registered successfully'}), 201

    except mysql.connector.Error as err:
        logging.error(f"MySQL Error: {err}")
        if err.errno == errorcode.ER_DUP_ENTRY:
            return jsonify({'error': 'Username or email already exists'}), 409
        return jsonify({'error': str(err)}), 500

    except Exception as e:
        logging.error(f"Error: {e}")
        return jsonify({'error': str(e)}), 400

# Route for User Sign-In
@app.route('/api/signin', methods=['POST'])
def signin():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401

        user.pop('password')  # Exclude password from the response
        return jsonify({'message': 'Sign-in successful', 'user': user}), 200

    except mysql.connector.Error as err:
        logging.error(f"MySQL Error: {err}")
        return jsonify({'error': 'Database error. Please try again later.'}), 500

    except Exception as e:
        logging.error(f"Error: {e}")
        return jsonify({'error': 'Server error. Please try again later.'}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    app.run(debug=True)
