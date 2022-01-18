""" Video from
https://www.youtube.com/watch?v=8aTnmsDMldY
"""

from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, String, Integer, create_engine
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisisthesecretkey'
conn = 'sqlite:////Users/denesgeza/Dropbox/Python/Projects/Flask/database.db'
engine = create_engine(conn, echo=True)
Bootstrap(app)
Session = sessionmaker()
Base = declarative_base()
local_session = Session(bind=engine)


class User(Base):

    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(15), unique=True)
    email = Column(String(50), unique=True)
    password = Column(String(80), unique=True)


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = local_session.query(User).filter(User.username == form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                return redirect(url_for('dashboard'))
            else:
                return '<h1>Invalid username or password</h1>'
    return render_template('login.html', form=form)


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        local_session.add(new_user)
        local_session.commit()
        return '<h1> New user has been created! </h1>'
    return render_template('signup.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.run(debug=True)
