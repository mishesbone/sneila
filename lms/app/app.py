from flask import Flask, render_template, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from wtforms import StringField, PasswordField, TextAreaField, SubmitField,BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo
import secrets
from flask_wtf import FlaskForm
from datetime import datetime, timedelta
from flask_user import UserManager, SQLAlchemyAdapter
from functools import wraps

# Initialize Flask app, SQLAlchemy, Bcrypt, and LoginManager
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:Invincible0!@localhost/lms'
app.config['USER_APP_NAME'] = 'RoboTek Academy'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'signin'
login_manager.login_message_category = 'info'



# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Define User, Course, and Enrollment models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    enrollments = db.relationship('Enrollment', backref='user', lazy=True)
    role = db.Column(db.String(20), nullable=False, default='student')

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    enrollments = db.relationship('Enrollment', backref='course', lazy=True)

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    # Your code to load a user from the database based on user_id
    return User.query.get(int(user_id))


class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    terms_and_conditions = BooleanField('I accept the Terms and Conditions', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class SigninForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class CourseForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Create Course')
    
    
db_adapter = SQLAlchemyAdapter(db, User)
user_manager = UserManager(db_adapter, app)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Home page route
@app.route('/')
def home():
    courses = Course.query.all()
    return render_template('home.html', courses=courses)

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('signin'))
    return render_template('register.html', form=form)

# Login route
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = SigninForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('signin.html', form=form)

# Dashboard route (replace with your actual dashboard logic)
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required  # This decorator ensures only authenticated users can access the dashboard
def dashboard():
    return render_template('dashboard.html')


# Logout route
@app.route('/signout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/create_course', methods=['GET', 'POST'])
@login_required
@admin_required  # Only administrators can create courses
def create_course():
    form = CourseForm()
    if form.validate_on_submit():
        course = Course(title=form.title.data, description=form.description.data)
        db.session.add(course)
        db.session.commit()
        flash('Course created successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('create_course.html', form=form)


# Enroll in a course route
@app.route('/enroll/<int:course_id>')
@login_required
def enroll(course_id):
    course = Course.query.get_or_404(course_id)
    enrollment = Enrollment(user_id=current_user.id, course_id=course_id)
    db.session.add(enrollment)
    db.session.commit()
    flash('Enrolled in the course!', 'success')
    return redirect(url_for('home'))

# Course details route
@app.route('/course/<int:course_id>')
@login_required
def course_details(course_id):
    course = Course.query.get_or_404(course_id)
    return render_template('course_details.html', course=course)

# Route for the Terms and Conditions page
@app.route('/terms-and-conditions')
def terms_and_conditions():
    return render_template('terms_and_conditions.html')

if __name__ == '__main__':
    app.run(debug=True)
    admin_users = User.query.filter_by(role='admin').all()
    for user in admin_users:
        print(f"Username: {user.username}, Email: {user.email}")


