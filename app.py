from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from flask_migrate import Migrate
from sqlalchemy import func
from db_setup import db
from datetime import datetime

app = Flask(__name__)
app.config.from_object('config')
db.init_app(app)

# Import models after db initialization
from models import User, Book

# Session configuration
app.secret_key = 'e590da20288293dfb8fd273c915ba94e'
app.config['SESSION_TYPE'] = 'filesystem'  # Capitalized SESSION_TYPE for session storage

# Initialize Flask-Session
Session(app)

migrate = Migrate(app, db)

@app.before_request
def create_tables():
    if not hasattr(app, 'tables_created'):
        db.create_all()
        app.tables_created = True

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Log in failed. Please check your email and password.')
            return redirect(url_for('login'))
        
        session['user_id'] = user.id
        session['user_role'] = user.role

        flash('Logged in successfully!')
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        role = request.form['role']  # 'admin' or 'user'

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in or use a different email.')
            return redirect(url_for('login'))
        
        new_user = User(name=name, email=email, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    search = request.args.get('search')
    if search:
        books = Book.query.filter(Book.title.ilike(f'%{search}%')).all()
    else:
        books = Book.query.all()

    total_books = Book.query.count()
    total_users = User.query.count()
    total_categories = db.session.query(func.count(Book.category.distinct())).scalar()

    if session.get('user_role') == 'admin':
        return render_template('admin_dashboard.html', books=books, total_books=total_books, total_users=total_users, total_categories=total_categories)
    else:
        return redirect(url_for('login'))

@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if session.get('user_role') == 'admin':
        if request.method == 'POST':
            title = request.form['title']
            author = request.form['author']
            category = request.form.get('category', 'Uncategorized')  # Default to 'Uncategorized' if no category is provided
            
            new_book = Book(title=title, author=author, category=category)
            db.session.add(new_book)
            db.session.commit()
            flash('Book added successfully.')
            return redirect(url_for('admin_dashboard'))
        
        return render_template('add_book.html')
    else:
        return redirect(url_for('login'))

@app.route('/edit_book/<int:book_id>', methods=['GET', 'POST'])
def edit_book(book_id):
    if session.get('user_role') == 'admin':
        book = Book.query.get_or_404(book_id)
        if request.method == 'POST':
            book.title = request.form['title']
            book.author = request.form['author']
            book.category = request.form['category']
            db.session.commit()
            flash('Book updated successfully.')
            return redirect(url_for('admin_dashboard'))
        
        return render_template('edit_book.html', book=book)
    else:
        return redirect(url_for('login'))

@app.route('/delete_book/<int:book_id>')
def delete_book(book_id):
    if session.get('user_role') == 'admin':
        book = Book.query.get_or_404(book_id)
        db.session.delete(book)
        db.session.commit()
        flash('Book deleted successfully.')
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/user_dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if session.get('user_role') == 'user':
        search_query = request.args.get('search', '')

        if search_query:
            books = Book.query.filter(Book.title.ilike(f'%{search_query}%')).all()
        else:
            books = Book.query.all()

        return render_template('user_dashboard.html', books=books, search_query=search_query)
    else:
        return redirect(url_for('login'))

@app.route('/user_management')
def user_management():
    users = User.query.all()  # Fetch all users
    return render_template('admin_dashboard.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['GET'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_user_role/<int:user_id>', methods=['GET', 'POST'])
def edit_user_role(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        new_role = request.form['role']
        user.role = new_role
        db.session.commit()
        flash('User role updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('edit_user_role.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!')
    return redirect(url_for('home'))

@app.route('/profile')
def profile():
    if 'user_id' not in session or session.get('user_role') != 'user':
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])  # Get logged-in user details
    return render_template('profile.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
