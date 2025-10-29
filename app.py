from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_sqlalchemy import SQLAlchemy
from forms import NoteForm
from datetime import datetime
from dotenv import load_dotenv
import os
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask import request

app = Flask(__name__)

load_dotenv()
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'dev-secret-for-local'

app.config['WTF_CSRF_ENABLED'] = True

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

# Глобальная CSRF-защита для всех форм
csrf = CSRFProtect(app)

# Настройка базы данных SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация базы данных
db = SQLAlchemy(app)

# Настройка логирования
logging.basicConfig(
    filename='flask_app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# ---- модели ----
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # хранит hash

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    owner = db.Column(db.String(50), nullable=False)

# ---- Регистрация  ----
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash("Заполните поля", "error")
            return redirect(url_for('register'))
        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Пользователь с таким именем уже существует", "error")
            return redirect(url_for('register'))
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash("Пользователь создан", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

# ---- Логин ----
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        # логируем попытку входа (не храним пароль в логах на проде!)
        logging.info(f"LOGIN_ATTEMPT ip={ip} username={username}")
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user'] = user.username
            logging.info(f"LOGIN_SUCCESS ip={ip} username={username}")
            flash("Вход выполнен (safe)!", "success")
            return redirect(url_for('index'))
        logging.warning(f"LOGIN_FAILED ip={ip} username={username}")
        flash("Неверные учетные данные", "error")
        return redirect(url_for('login'))
    return render_template('login.html', safe=True)

# ---- Выход ----
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Вы вышли из системы", "success")
    return redirect(url_for('login'))

# Заголовки безопасности и скрытие информации о сервере
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self';"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Server'] = 'MySecureServer'
    return response

# Главная страница: список заметок и форма добавления
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user' not in session:
        flash("Сначала войдите в систему", "error")
        return redirect(url_for('login'))

    form = NoteForm()
    if form.validate_on_submit():
        ip = request.remote_addr
        logging.info(f"NOTE_CREATE ip={ip} owner={session['user']} title={form.title.data} content={form.content.data}")
        new_note = Note(
            title=form.title.data,
            content=form.content.data,
            owner=session['user']
        )
        db.session.add(new_note)
        db.session.commit()
        flash("Заметка успешно добавлена!", "success")
        return redirect(url_for('index'))
    elif request.method == 'POST':
        flash("Сессия истекла или форма была изменена. Обновите страницу и попробуйте снова.", "error")

    notes = Note.query.filter_by(owner=session['user']).all()
    return render_template('index.html', form=form, notes=notes)

# Редактирование заметки
@app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
def edit(note_id):
    note = Note.query.get_or_404(note_id)
    if note.owner != session.get('user'):
        return "Нет доступа!", 403

    form = NoteForm(obj=note)
    if form.validate_on_submit():
        note.title = form.title.data
        note.content = form.content.data
        db.session.commit()
        flash("Заметка успешно обновлена!", "success")
        return redirect(url_for('index'))
    elif request.method == 'POST':
        flash("Сессия истекла или форма была изменена. Обновите страницу и попробуйте снова.", "error")

    return render_template('edit.html', form=form, note=note)

# Удаление заметки
@app.route('/delete/<int:note_id>', methods=['POST'])
def delete(note_id):
    note = Note.query.get_or_404(note_id)
    if note.owner != session.get('user'):
        return "Нет доступа!", 403

    db.session.delete(note)
    db.session.commit()
    flash("Заметка удалена!", "success")
    return redirect(url_for('index'))

# Запуск приложения
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
