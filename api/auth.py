from flask import request, jsonify
from api.config import app, mysql
from flask_mysqldb import MySQLdb
from werkzeug.security import generate_password_hash, check_password_hash
from utils.functions import *

@app.route("/api/auth/", methods=["GET"])
@token_required
def auth():
    return jsonify({'user': request.user}), 200

@app.route("/api/auth/signin/", methods=["POST"])
def signin():
    if (
        request.method == "POST"
        and "email" in request.form
        and "password" in request.form
    ):
        email = request.form["email"]
        password = request.form["password"]
        user_find_query = "SELECT * FROM Users WHERE email = %s"
        try:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(user_find_query, (email,))
            user = cursor.fetchone()
            if user is None:
                return {"message": "User not exist"}, 404
            else:
                user_firstName = user['firstName']
                user_lastName = user['lastName']
                user_email = user['email']
                user_password = user['password']
                if user_password and check_password_hash(user_password, password) == True:
                    payload = {
                        "firstName": user_firstName,
                        "lastName": user_lastName,
                        "email": user_email,
                    }
                    token = encode_auth_token(payload)
                    return jsonify({"token": token, "message": "User Logged in successfully"}), 200
                    
        except Exception as e:
            print("Database connection failed due to {}".format(e))
            return jsonify({"message": "Database Error"}), 400
    else:
        print("Missing fields")
        return jsonify({"status": 400, "message": "Missing fields"}), 400

@app.route("/api/auth/signup/", methods=["POST"])
def register():
    print(request.form["firstName"])
    if (
        request.method == "POST"
        and "firstName" in request.form
        and "lastName" in request.form
        and "email" in request.form
        and "password" in request.form
    ):
        firstName = request.form["firstName"]
        lastName = request.form["lastName"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        create_table_query = '''
            CREATE TABLE IF NOT EXISTS Users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                firstName VARCHAR(255) NOT NULL,
                lastName VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                password VARCHAR(255) NOT NULL
            )
        '''

        try:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(create_table_query)
            
            email_check_query = "SELECT * FROM Users WHERE email = %s"
            cursor.execute(email_check_query, (email,))
            
            exist_users = cursor.fetchall()
            if len(exist_users) > 0:
                return jsonify({"message": "User already registered."}), 409
            else:
                user_register_query = "INSERT INTO Users (firstName, lastName, email, password) VALUES (%s, %s, %s, %s)"
                cursor.execute(user_register_query, (firstName, lastName, email, password))
                mysql.connection.commit()
                cursor.close()
                return jsonify({"message": "User Registered successfully"}), 200
        except Exception as e:
            print("Database connection failed due to {}".format(e))
            return jsonify({"message": "Database Error"}), 400
    else:
        print("Missing fields")
        return jsonify({"status": 400, "message": "Missing fields"}), 400