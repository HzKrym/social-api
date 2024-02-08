from flask import Flask, request, abort, jsonify
from typing_extensions import Self, List
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import and_, or_
from datetime import datetime

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

    def check_password(self, password: str):
        return bcrypt.check_password_hash(self.password, password)
    
    @classmethod
    def find_by_username(cls, username: str) -> Self:
        return cls.query.filter_by(username=username).first()
    
class Message(db.Model):
    __tablename__ = 'message'

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(256), nullable=False)
    from_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    to_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    datetime = db.Column(db.DateTime)

    def __init__(
            self, 
            message: str, 
            from_id: int, 
            to_id: int
            ):
        self.message = message
        self.from_id = from_id
        self.to_id = to_id
        self.datetime = datetime.now()

    def to_dict(self) -> dict:
        from_user: User = User.query.get(self.from_id)
        to_user: User = User.query.get(self.to_id)
        return {
            'id': self.id,
            'message': self.message,
            'from': {
                'id': self.from_id,
                'username': from_user.username,
                'last_name': from_user.last_name,
                'first_name': from_user.first_name
            },
            'to': {
                'id': self.to_id,
                'username': to_user.username,
                'last_name': to_user.last_name,
                'first_name': to_user.first_name,
            },
            'datetime': self.datetime.__str__()
        }


with app.app_context():
    db.create_all()

def is_not_added_message(list: List[dict], message: Message) -> bool:
    for message_in_list in list:
        if message_in_list['from']['id'] == message.from_id or message_in_list['to']['id'] == message.from_id:
            return False
        if message_in_list['from']['id'] == message.to_id or message_in_list['to']['id'] == message.to_id:
            return False
    return True

@app.route('/')
def main():
    return 'Test'

@app.route('/send', methods=['POST'])
def send_message():
    if not request.json or not 'message' in request.json or not 'from' in request.json or not 'to' in request.json:
        abort(400)
    
    message = request.json.get('message', '')
    from_id = request.json.get('from', '')
    to_id = request.json.get('to', '')

    new_message = Message(message, from_id, to_id)
    db.session.add(new_message)
    db.session.commit()
    return ('', 204)

@app.route('/message', methods=['POST'])
def get_messages():
    if not request.json or not 'user_id' in request.json:
        abort(400)

    user_id = request.json.get('user_id', '')
    messages: List[Message] = Message.query.where(
        or_(
            Message.from_id == user_id,
            Message.to_id == user_id
        )
        ).order_by(Message.datetime.desc()).all()
    last_messages: List[dict] = []
    for message in messages:
        if is_not_added_message(last_messages, message):
            last_messages.append(message.to_dict())
    return { 'last_messages': last_messages }

@app.route('/user-message', methods=['POST'])
def get_messages_by_user():
    if not request.json or not 'user_id' in request.json or not 'friend_id' in request.json:
        abort(400)
    
    user_id = request.json.get('user_id', '')
    friend_id = request.json.get('friend_id', '')
    messages: List[Message] = Message.query.order_by(Message.datetime.desc()).all()
    messages_list: List[dict] = []
    for message in messages:
        if (message.from_id == user_id and message.to_id == friend_id) or (message.from_id == friend_id and message.to_id == user_id):
            messages_list.append(message.to_dict())
    return { 'messages_list': messages_list }

@app.route('/register', methods=['POST'])
def register():
    if not request.json or not 'username' in request.json or not 'password' in request.json:
        abort(400)
    
    username = request.json.get('username', '')
    pswrd = request.json.get('password', '')
    first_name = request.json.get('first_name', '')
    last_name = request.json.get('last_name', '')

    user = User.find_by_username(username)
    if not user == None:
        abort(401)

    new_user = User(
        username = username,
        first_name = first_name,
        last_name = last_name
    )
    hash_bytes = bcrypt.generate_password_hash(pswrd)
    new_user.password = hash_bytes.decode('utf-8')

    db.session.add(new_user)
    db.session.commit()

    return { 'id': new_user.id }

    
@app.route('/login', methods=['POST'])
def login():
    if not request.json or not 'username' in request.json or not 'password' in request.json:
        abort(400)
    
    username = request.json.get('username', '')
    pswrd = request.json.get('password', '')

    user = User.find_by_username(username)
    if user == None:
        abort(401)
    if user.check_password(pswrd):
        return {'id': user.id}
    else:
        abort(401)
    
@app.route('/user/<username>', methods=['GET'])
def user(username):
    user = User.find_by_username(username)
    if user == None:
        user = User.query.get(username)
        if user == None:
            abort(404)
    return {
        'id': user.id,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name
    }