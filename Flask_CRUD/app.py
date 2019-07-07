# All necessary imports
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, BooleanField, PasswordField
from wtforms.validators import Length, Email, InputRequired
from flask_bootstrap import Bootstrap
from flask_login import login_required, UserMixin, LoginManager, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

#  Instantiate the app
app = Flask(__name__)

# Configure the app
app.config.from_pyfile('config.cfg')

# Use SQLAlchemy to create a database for the app
db = SQLAlchemy(app)

# Use Flask-bootstrap with this app
Bootstrap(app)

# Use Flask-login to handle User-Sessions
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create a class for the login form using Flaskform
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=5, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')

# Create a class for the registration form using Flaskform
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=5, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    email = StringField('Email', validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)])
    recaptcha = RecaptchaField()

# Create a Users table in the database to store user data
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    email = db.Column(db.String(50), unique=True)
    # The next column to establish a one-to-many relationship with the 'Tasks' table
    tasks = db.relationship('Tasks', backref='username')
    # backref creates a virtual column in the table 'Tasks', which can be accessed

# Create a Tasks table in the database to handle tasks of all users
class Tasks(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime(), default=datetime.utcnow)
    # The next column is to establish a one-to-many relationship with the 'Users' table
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # ForeignKey is looking for the actual table named users, hence in lowercase

    def __refr__(self):
        return '<Task %r>' %self.id

# Flask-login feature to handle user-session
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Index page
@app.route('/')
def index():
    return render_template('index.html')

# Login protected home page to display the tasks
@app.route('/task', methods=['POST', 'GET'])
@login_required
def task():
    if request.method == 'POST':
        # Getting the task's content from the user
        task_content = request.form['content']
        # Check if the user has entered only whitespaces
        if task_content and not task_content.isspace():
            # To prevent user from entering duplicates of the tasks
            count = 0
            all_tasks = Tasks.query.filter_by(user_id=current_user.id).all()
            for task in all_tasks:
                # Converts both strings to lower case and compares them
                if task.content.lower() == task_content.lower():
                    count = 1       
            if count > 0:
                flash('Task already exists!', category='info')
                return redirect(url_for('task'))
            # Adding the user's task to the 'Tasks' table
            else:
                # Using one-to-many relationship to add record to the Tasks table
                new_task = Tasks(content=task_content, username=current_user)
                try:
                    db.session.add(new_task)
                    db.session.commit()
                    flash(current_user.username + ', your task has been added!', category='info')
                    return redirect(url_for('task'))
                except:
                    flash('There was a problem in adding a new task. Please try again', category='info')
                    return redirect(url_for('task'))

        # To prevent a user from adding an empty field as a new task
        else:
            flash('No task provided. Cannot add an empty field', category='info')
            return redirect(url_for('task'))
                
    # If 'GET' request first check if the user had any previous tasks already added to the 'tasks' table
    task_user_id = Tasks.query.filter_by(user_id=current_user.id).first()
    if task_user_id:
        all_tasks = Tasks.query.filter_by(user_id=current_user.id).all()
        return render_template('task.html', tasks=all_tasks)
    # If new user, pass an empty task object to 'task.html'
    else:
        return render_template('task.html', task='')
      
# Registration route
@app.route('/register', methods=['POST', 'GET'])
def register():
    # Create an instance(object) of the class for registration form
    form = RegisterForm()
    if request.method == 'POST':   
        # Add the new user record into 'Users' table with proper credentials and redirect to login page 
        if form.validate_on_submit():
            registered_user = Users.query.filter_by(username=form.username.data).first()
            if not registered_user:
                hashed_password = generate_password_hash(form.password.data, method='sha256')
                new_user = Users(username=form.username.data, password=hashed_password, email=form.email.data)
                db.session.add(new_user)
                db.session.commit()
                flash('Sign-up was successful, now you can login!', category='success')
                return redirect(url_for('login'))
            else:
                flash(registered_user.username + ' is already registered. Please try another username', category='warning')
                return redirect(url_for('register'))
    return render_template('register.html', form=form)

# Login an already registered user
@app.route('/login', methods=['POST', 'GET'])
def login():
    # Create an instance(object) of the class for registration form
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            # Check if the user is registred
            user = Users.query.filter_by(username=form.username.data).first()
            if user:
                # Check if the input password matches with the data in the 'Users' table
                if check_password_hash(user.password, form.password.data):
                    # Login user if provided with correct credentials
                    login_user(user, remember=form.remember.data)
                    flash('Logged in successfully!', category='success')
                    return redirect(url_for('task'))
                flash('Invalid username or password. Please try again', category='warning')
                return redirect(url_for('login'))
            flash('Incorrect username. Please register if you are a new user', category='warning')
    return render_template('login.html', form=form)

# Logout an user using flask-login function
@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Update any task in the user's todo list
@app.route('/update/<int:id>', methods=['POST', 'GET'])
@login_required
# Recieves a 'id' parameter to locate the particular task's record in the 'tasks' table
def update(id):
    # Query the task using the id of the task from the 'Tasks' table
    task = Tasks.query.filter_by(id=id).first()
    if request.method == 'POST':
        # Checks that the task is actually updated and also that it is not left blank
        if not task.content == request.form['content'] and request.form['content']:
            # Overwrite the content column of the particular task's record
            task.content = request.form['content']
            try:
                db.session.commit()
                flash('Task has been updated.', category='info')
                return redirect(url_for('task'))
            except:
                flash('There was an issue in updating your task.', category='info')
                return redirect (url_for('update', id=id))
        else:
            flash('Please update the task.', category='warning')
            return redirect(url_for('update', id=id))
    else:
        return render_template('update.html', task=task)

# Delete any task in the user's todo list
@app.route('/delete/<int:id>', methods=['POST', 'GET'])
@login_required
# Recieves a 'id' parameter to locate the particular task's record in the 'tasks' table
def delete(id):
    # Query the task using the id of the task from the 'Tasks' table
    task_to_delete = Tasks.query.filter_by(id=id).first()
    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        flash('Task has been deleted!', category='success')
        return redirect(url_for('task'))
    except:
        flash('Your task could not be deleted from the list', category='info')
        return redirect(url_for('task'))

# Delete all tasks in the user's todo list
@app.route('/delete_all_tasks', methods=['POST', 'GET'])
@login_required
def delete_all_tasks():
    tasks_to_delete = Tasks.query.filter_by(user_id=current_user.id).all()
    for task in tasks_to_delete:
        db.session.delete(task)
        db.session.commit()
    flash('All tasks deleted', category='success')
    return redirect(url_for('task'))

# Run the app in debug mode when it's run through this module
if __name__ == '__main__':
    app.run(debug=True)