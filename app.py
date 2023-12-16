from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import Integer, String, Column
from sqlalchemy.orm import DeclarativeBase

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

    @property
    def password(self):
        raise AttributeError("Password write-only property")
    
    @password.setter
    def set_password(self, password):
        hash_bytes = bcrypt.generate_password_hash(password)
        self.password = hash_bytes.decode('utf-8')

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