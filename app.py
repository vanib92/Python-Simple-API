from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///apidb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True

db.create_all()
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}),401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'You need admin access to do that!'})

    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'user' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'You need admin access to do that!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'You need admin access to do that!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'You need admin access to do that!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user is now admin!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'You need admin access to do that!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password,auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/note', methods=['GET'])
@token_required
def get_all_notes(current_user):
    notes = Note.query.filter_by(user_id=current_user.id).all()

    output = []

    for note in notes:
        note_data = {}
        note_data['id'] = note.id
        note_data['text'] = note.text
        note_data['complete'] = note.complete
        output.append(note_data)

    return jsonify({'notes' : output})

@app.route('/note/<note_id>', methods=['GET'])
@token_required
def get_one_note(current_user, note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()

    if not note:
        return jsonify({'message' : 'No note found!'})
    note_data = {}
    note_data['id'] = note.id
    note_data['text'] = note.text
    note_data['complete'] = note.complete

    return jsonify(note_data)

@app.route('/note', methods=['POST'])
@token_required
def create_note(current_user):
    data = request.get_json()

    new_note = Note(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_note)
    db.session.commit()

    return jsonify({'message' : 'Note created!'})

@app.route('/note/<note_id>', methods=['PUT'])
@token_required
def complete_note(current_user, note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()

    if not note:
        return jsonify({'message': 'No note found!'})

    note.complete = True
    db.session.commit()

    return jsonify({'message' : 'Note has been completed!'})

@app.route('/note/<note_id>', methods=['DELETE'])
@token_required
def delete_note(current_user, note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()

    if not note:
        return jsonify({'message': 'No note found!'})

    db.session.delete(note)
    db.session.commit()

    return jsonify({'message' : 'Note has been deleted!'})

if __name__ == '__main__':
    app.run(debug=True)
