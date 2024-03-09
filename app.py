# Import necessary libraries and modules from Flask, Flask-SQLAlchemy, Flask-Login, and Werkzeug
from flask import Flask, request, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the Flask application
app = Flask(__name__)
# Set secret key for the application to securely sign the session cookie
app.config['SECRET_KEY'] = 'your_secret_key_here'
# Configure the SQLAlchemy database URI to use a SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
# Disable the signal to track modifications of objects and emit signals
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Initialize the SQLAlchemy database instance
db = SQLAlchemy(app)

# Initialize the login manager to handle user authentication
login_manager = LoginManager()
login_manager.init_app(app)
# Specify the view to redirect users to when they need to login
login_manager.login_view = 'login'

# Define the Todo model for the todo list items
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(150), nullable=False)
    completed = db.Column(db.Boolean, default=False)

# Define the User model for user authentication, inheriting from UserMixin for Flask-Login
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))

    # Method to set the user's password hash
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Method to check if the provided password matches the hash
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Callback to load the user object from the user ID stored in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route for handling the login page and user authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

# Route for handling user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# Route for handling user logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Route for the home page to display and add todo items
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        task_content = request.form.get('content')
        new_task = Todo(task=task_content, completed=False)

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect(url_for('home'))
        except:
            return 'There was an issue adding your task.'

    else:
        tasks = Todo.query.order_by(Todo.id).all()
        return render_template('home.html', tasks=tasks)

# Route to delete a todo item
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)
    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect(url_for('home'))
    except:
        return 'There was a problem deleting that task.'

# Route to mark a todo item as complete or incomplete
@app.route('/complete/<int:id>')
@login_required
def complete(id):
    task_to_complete = Todo.query.get_or_404(id)
    try:
        task_to_complete.completed = not task_to_complete.completed
        db.session.commit()
        return redirect(url_for('home'))
    except:
        return 'There was a problem updating that task.'

# Main block to run the Flask application
if __name__ == "__main__":
    # Create all the database tables before running the app
    with app.app_context():
        db.create_all()
    app.run(debug=True)  # Run the application with debug mode enabled