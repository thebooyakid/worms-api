from flask import Flask, make_response, request, g
import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

class Config():
    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get("SQLALCHEMY_TRACK_MODIFICATIONS")


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
basic_auth = HTTPBasicAuth()

@basic_auth.verify_password
def verify_password(email, password):
    u = User.query.filter_by(email=email).first()
    if u is None:
        return False
    g.current_user = u
    return u.check_hashed_password(password)


class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, index=True, unique=True)
    password = db.Column(db.String)
    recipes = db.relationship("Recipe", backref="author", lazy="dynamic", cascade='all, delete-orphan')

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

    def __repr__(self):
        return f'<{self.user_id}|{self.email}>'

    def from_dict(self, data):
        self.email = data['email']
        self.password = self.hash_password(data['password'])

    def to_dict(self):
        return {"user_id": self.user_id, "email": self.email}

class Recipe(db.Model):
    recipe_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String)
    body =  db.Column(db.Text)
    user_id = db.Column(db.ForeignKey('user.user_id'))

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return f'<{self.recipe_id}|{self.title}>'

    def from_dict(self,data):
        self.title = data['title']
        self.body = data['body']
        self.user_id = data['user_id']

    def to_dict(self):
        return {"user_id": self.user_id, "title": self.title, "body":self.body, "recipe_id":self.recipe_id}

@app.get('/login')
@basic_auth.login_required()
def login():
    return make_response(f"valid login for user id: {g.current_user.user_id}", 200)

@app.get('/user')
def get_users():
    return make_response({"users":[user.to_dict() for user in User.query.all()]}, 200)

@app.get('/user/<int:user_id>')
def get_user(user_id):
    return make_response(User.query.get(user_id).to_dict(), 200)

@app.post('/user')
def post_user():
    data = request.get_json()
    new_user = User()
    new_user.from_dict(data)
    new_user.save()
    return make_response("success",200)

@app.put('/user/<int:user_id>')
def put_user(user_id):
    data = request.get_json()
    user=User.query.get(user_id)
    user.from_dict(data)
    user.save()
    return make_response("success",200)

@app.delete('/user/<int:user_id>')
def delete_user(user_id):
    User.query.get(user_id).delete()
    return make_response("success",200)


@app.get('/recipe')
def get_recipes():
    return make_response({"recipes":[recipe.to_dict() for recipe in Recipe.query.all()]}, 200)

@app.get('/recipe/<int:recipe_id>')
def get_recipe(recipe_id):
    return make_response(Recipe.query.get(recipe_id).to_dict(), 200)

@app.post('/recipe')
def post_recipe():
    data = request.get_json()
    new_recipe = Recipe()
    new_recipe.from_dict(data)
    new_recipe.save()
    return make_response("success",200)

@app.put('/recipe/<int:recipe_id>')
def put_recipe(recipe_id):
    data = request.get_json()
    recipe=Recipe.query.get(recipe_id)
    recipe.from_dict(data)
    recipe.save()
    return make_response("success",200)

@app.delete('/recipe/<int:recipe_id>')
def delete_recipe(recipe_id):
    Recipe.query.get(recipe_id).delete()
    return make_response("success",200)

@app.get('/recipe/user/<int:user_id>')
def get_recipes_by_user_id(user_id):
    return make_response({"recipes":[recipe.to_dict() for recipe in User.query.get(user_id).recipes]},200)