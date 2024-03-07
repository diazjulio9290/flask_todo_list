

from flask import Flask, request, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(150), nullable=False)
    completed = db.Column(db.Boolean, default=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

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

# If you decide to add a route to mark tasks as complete or incomplete, it would look similar to the delete route

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

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
