from flask import Flask, request, abort, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import Integer, String, Column, create_engine
from sqlalchemy.orm import DeclarativeBase, Session

class Base(DeclarativeBase):
    pass

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db = SQLAlchemy(app, model_class=Base)
bcrypt = Bcrypt(app)

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    
    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()


with app.app_context():
    db.create_all()

@app.route("/")
def main():
    return "Test"

@app.route("/register", methods=['POST'])
def register():
    if not request.json or not 'username' in request.json or not 'password' in request.json:
        abort(400)
    
    username = request.json.get('username', '')
    pswrd = request.json.get('password', '')
    first_name = request.json.get('first_name', '')
    last_name = request.json.get('last_name', '')



    user = User.find_by_username(username)
    if not user == None:
        abort(400)

    new_user = User(
        username = username,
        first_name = first_name,
        last_name = last_name
    )
    hash_bytes = bcrypt.generate_password_hash(pswrd)
    new_user.password = hash_bytes.decode('utf-8')

    db.session.add(new_user)
    db.session.commit()

    return jsonify(
        id = new_user.id
    )

    
@app.route("/login", methods=['POST'])
def login():
    if not request.json or not 'username' in request.json or not 'password' in request.json:
        abort(400)
    
    username = request.json.get('username', '')
    pswrd = request.json.get('password', '')

    user = User.find_by_username(username)
    if user.check_password(pswrd):
        redirect(url_for('user', username=user.username))
    
@app.route("/user/<username>", methods=['GET'])
def user(username):
    user = User.find_by_username(username)
    return jsonify(
        id = user.id
    )