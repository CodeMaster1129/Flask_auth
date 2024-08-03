from flask import Flask
from flask_cors import CORS
from flask_mysqldb import MySQL

app = Flask(__name__)

CORS(app, origins="*", allow_headers="*")

app.config['MYSQL_HOST'] = 'hdf.cjwfktkwkbo1.us-east-1.rds.amazonaws.com'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_USER'] = 'admin'
app.config['MYSQL_PASSWORD'] = 'RDSHDFdb0510!'
app.config['MYSQL_DB'] = 'auth'
mysql = MySQL(app)