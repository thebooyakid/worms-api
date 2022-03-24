from flask import Flask, make_response, request, g, abort
import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime as dt, timedelta
# import secrets
from flask_cors import CORS

class Config():
    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get("SQLALCHEMY_TRACK_MODIFICATIONS")

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
basic_auth = HTTPBasicAuth()
# token_auth = HTTPTokenAuth()
cors = CORS(app)



@basic_auth.verify_password
def verify_password(email, password):
    u = User.query.filter_by(email=email.lower()).first()
    if u is None:
        return False
    g.current_user = u
    return u.check_hashed_password(password)

# @token_auth.verify_token
# def verify_token(token):
#     u = User.check_token(token) if token else None
#     g.current_user = u
#     return g.current_user or None

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, index=True, unique=True)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    password = db.Column(db.String)
    created_on = db.Column(db.DateTime, default=dt.utcnow)
    modified_on = db.Column(db.DateTime, onupdate=dt.utcnow)
    # token = db.Column(db.String, index=True, unique=True)
    # token_exp = db.Column(db.DateTime)

    # def get_token(self, exp=86400):
    #     current_time = dt.utcnow()
    #     if self.token and self.token_exp > current_time + timedelta(seconds=60):
    #         return self.token
    #     self.token = secrets.token_urlsafe(32)
    #     self.token_exp = current_time + timedelta(seconds=exp)
    #     self.save()
    #     return self.token

    # def revoke_token(self):
    #     self.token_exp = dt.utcnow() - timedelta(seconds=61)

    # @staticmethod
    # def check_token(token):
    #     u = User.query.filter_by(token=token).first()
    #     if not u or u.token_exp < dt.utcnow():
    #         return None
    #     return u

    def __repr__(self):
        return f'<{self.user_id}|{self.email}>'
    
    def hash_password(self, original_password):
        return generate_password_hash(original_password)

    def check_hashed_password(self, login_password):
        return check_password_hash(self.password, login_password)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def from_dict(self, data):
        for field in ['email', 'first_name', 'last_name', 'password']:
            if field in data:
                if field == 'password':
                    setattr(self, field, self.hash_password(data[field]))
                else:
                    setattr(self, field, data[field])

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "created_on": self.created_on,
            "modified_on": self.modified_on,
            # "token": self.token
        }

    # def register(self, data):
    #     self.email = data['email']
    #     self.first_name = data['first_name']
    #     self.last_name = data['last_name']
    #     self.password = self.hash_password(data['password'])


class Painting(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    medium = db.Column(db.String)
    title = db.Column(db.String)
    description = db.Column(db.String)
    img = db.Column(db.String)
    created_on = db.Column(db.DateTime, default=dt.utcnow)

    def __repr__(self):
        return f'<{self.id}|{self.title}>'

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def from_dict(self, data):
        for field in ['medium', 'title', 'description', 'img']:
            if field in data:
                setattr(self, field, data[field])

    def to_dict(self):
        return {
            "id": self.id,
            "medium": self.medium,
            "title": self.title,
            "description": self.description,
            "img": self.img,
            "created_on": self.created_on
        }

class Pin(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String)
    description = db.Column(db.String)
    img = db.Column(db.String)
    created_on = db.Column(db.DateTime, default=dt.utcnow)

    def __repr__(self):
        return f'<{self.id}|{self.title}>'

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def from_dict(self, data):
        for field in ['title', 'description', 'img']:
            if field in data:
                setattr(self, field, data[field])

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "img": self.img,
            "created_on": self.created_on
        }

class Custom(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    category = db.Column(db.String)
    medium = db.Column(db.String)
    title = db.Column(db.String)
    description = db.Column(db.String)
    img = db.Column(db.String)
    created_on = db.Column(db.DateTime, default=dt.utcnow)

    def __repr__(self):
        return f'<{self.id}|{self.title}>'

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def from_dict(self, data):
        for field in ['category', 'medium', 'title', 'description', 'img']:
            if field in data:
                setattr(self, field, data[field])

    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "medium": self.medium,
            "title": self.title,
            "description": self.description,
            "img": self.img,
            "created_on": self.created_on
        }

### API Routes ###

@app.get('/login')
@basic_auth.login_required()
def login():
    g.current_user.get_token()
    return make_response(g.current_user.to_dict(), 200)

# @app.get('/user')
# def get_users():
#     return make_response({"users":[user.to_dict() for user in User.query.all()]}, 200)

# @app.get('/user/<int:user_id>')
# def get_user(user_id):
#     return make_response(User.query.get(user_id).to_dict(), 200)

@app.post('/user')
def post_user():
    data = request.get_json()
    if User.query.filter_by(email=data.get('email')).first():
        abort(422)
    new_user = User()
    new_user.from_dict(data)
    new_user.save()
    return make_response("New User Registered", 200)

@app.put('/user/<int:id>')
def put_user(user_id):
    data = request.get_json()
    user = User.query.get(user_id)
    user.from_dict(data)
    user.save()
    return make_response("Profile Updated", 200)

@app.delete('/user/<int:id>')
def delete_user(user_id):
    User.query.get(user_id).delete()
    return make_response("User Successfully Deleted", 200)

##############

@app.get('/painting')
def get_paintings():
    return make_response({'paintings':[painting.to_dict() for painting in Painting.query.all()]}, 200)

@app.get('/painting/<int:id>')
def get_painting(id):
    return make_response(Painting.query.filter_by(id=id).first().to_dict(), 200)

@app.post('/painting')
def post_painting():
    data = request.get_json()
    new_painting = Painting()
    new_painting.from_dict(data)
    new_painting.save()
    return make_response('Painting added', 200)

@app.get('/pin')
def get_pins():
    return make_response({'pin':[pin.to_dict() for pin in Pin.query.all()]}, 200)

@app.get('/pin/<int:id>')
def get_pin(id):
    return make_response(Pin.query.filter_by(id=id).first().to_dict(), 200)

@app.post('/pin')
def post_pin():
    data = request.get_json()
    new_painting = Pin()
    new_painting.from_dict(data)
    new_painting.save()
    return make_response('Pin added', 200)

@app.get('/custom')
def get_customs():
    return make_response({'customs':[custom.to_dict() for custom in Custom.query.all()]}, 200)

@app.get('/custom/<int:id>')
def get_custom(id):
    return make_response(Custom.query.filter_by(id=id).first().to_dict(), 200)

@app.post('/custom')
def post_custom():
    data = request.get_json()
    new_painting = Custom()
    new_painting.from_dict(data)
    new_painting.save()
    return make_response('custom added', 200)

#########################

if __name__=="__main__":
    app.run(debug=True) 