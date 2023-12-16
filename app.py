from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db = SQLAlchemy(app, model_class=Base)

with app.app_context():
    db.create_all()

@app.route("/")
def main():
    return "Test"