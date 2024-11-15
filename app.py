from flask import Flask, request, render_template, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import pyodbc
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database connection string
conn_str = os.getenv('DATABASE_CONNECTION_STRING', 'DRIVER={ODBC Driver 17 for SQL Server};SERVER=PROHTYAGI\\SQLEXPRESS2022;DATABASE=Legal_Repo;UID=sa;PWD=welcome@12345')
conn = pyodbc.connect(conn_str)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name):
        self.email = email
        self.name = name
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    # Redirect to the login page when the app is accessed on the root URL
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect('/register')

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['name'] = user.name
            session['email'] = user.email
            return redirect('/index')
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

@app.route('/index')
def index():
    if 'name' in session:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT NameofActs FROM legalActs")
        acts = cursor.fetchall()
        user = User.query.filter_by(email=session['email']).first()
        return render_template('index.html', acts=acts, user=user)

    return redirect('/login')

@app.route('/act/<string:act_name>')
def act_details(act_name):
    cursor = conn.cursor()
    cursor.execute("SELECT Section, SecDesc FROM LegalActs WHERE NameofActs = ? ORDER BY try_CAST(CASE WHEN CHARINDEX('.', Section) > 0 AND CHARINDEX('-', Section) > 0 THEN LEFT(Section, CASE WHEN CHARINDEX('.', Section) < CHARINDEX('-', Section) THEN CHARINDEX('.', Section) - 1 ELSE CHARINDEX('-', Section) - 1 END) WHEN CHARINDEX('.', Section) > 0 THEN  SUBSTRING(Section, 1, CHARINDEX('.', Section) - 1) WHEN CHARINDEX('-', Section) > 0 THEN SUBSTRING(Section, 1, CHARINDEX('-', Section) - 1) ELSE Section END AS INT), CASE WHEN CHARINDEX('.', Section) > 0 AND CHARINDEX('-', Section) > 0 THEN LTRIM(SUBSTRING(Section, CASE WHEN CHARINDEX('.', Section) < CHARINDEX('-', Section) THEN CHARINDEX('.', Section) + 1 ELSE CHARINDEX('-', Section) + 1 END, LEN(Section))) WHEN CHARINDEX('.', Section) > 0 THEN LTRIM(SUBSTRING(Section, CHARINDEX('.', Section) + 1, LEN(Section))) WHEN CHARINDEX('-', Section) > 0 THEN LTRIM(SUBSTRING(Section, CHARINDEX('-', Section) + 1, LEN(Section))) ELSE Section END", (act_name,))
    sections = cursor.fetchall()
    return render_template('details.html', act_name=act_name, sections=sections)

@app.route('/filter', methods=['POST'])
def filter_sections():
    act_name = request.form['act_name']
    section_filter = request.form['section_filter']

    cursor = conn.cursor()
    cursor.execute("SELECT Section, SecDesc FROM LegalActs WHERE NameofActs = ? AND Section LIKE ? ORDER BY try_CAST(CASE WHEN CHARINDEX('.', Section) > 0 AND CHARINDEX('-', Section) > 0 THEN LEFT(Section, CASE WHEN CHARINDEX('.', Section) < CHARINDEX('-', Section) THEN CHARINDEX('.', Section) - 1 ELSE CHARINDEX('-', Section) - 1 END) WHEN CHARINDEX('.', Section) > 0 THEN  SUBSTRING(Section, 1, CHARINDEX('.', Section) - 1) WHEN CHARINDEX('-', Section) > 0 THEN SUBSTRING(Section, 1, CHARINDEX('-', Section) - 1) ELSE Section END AS INT), CASE WHEN CHARINDEX('.', Section) > 0 AND CHARINDEX('-', Section) > 0 THEN LTRIM(SUBSTRING(Section, CASE WHEN CHARINDEX('.', Section) < CHARINDEX('-', Section) THEN CHARINDEX('.', Section) + 1 ELSE CHARINDEX('-', Section) + 1 END, LEN(Section))) WHEN CHARINDEX('.', Section) > 0 THEN LTRIM(SUBSTRING(Section, CHARINDEX('.', Section) + 1, LEN(Section))) WHEN CHARINDEX('-', Section) > 0 THEN LTRIM(SUBSTRING(Section, CHARINDEX('-', Section) + 1, LEN(Section))) ELSE Section END", (act_name, f'%{section_filter}%'))
    filtered_sections = cursor.fetchall()

    return render_template('details.html', act_name=act_name, sections=filtered_sections, filter_applied=True)

@app.route('/logout')
def logout():
    session.pop('email', None)
    session.pop('name', None)
    flash('You have been logged out.')
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
