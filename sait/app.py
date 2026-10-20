from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db_connection, init_db
from config import Config
from datetime import datetime
import random
import string
import os

app = Flask(__name__)
app.config.from_object(Config)

# Инициализируем базу данных при запуске, если она еще не создана
if not os.path.exists(Config.DATABASE):
    init_db()

def generate_auth_code():
    """Генерирует случайный 6-значный код для 2FA."""
    return ''.join(random.choices(string.digits, k=6))

@app.route('/')
def index():
    """Главная страница — лента постов с фильтрацией."""
    conn = get_db_connection()
    
    # Получаем параметры фильтрации из GET-запроса
    filter_user = request.args.get('username', '').strip()
    sort_order = request.args.get('sort', 'desc').lower()
    
    # Базовый SQL-запрос для ленты с соединением таблицы пользователей и постов
    query = '''
        SELECT posts.*, users.nickname, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id
    '''
    params = []
    
    if filter_user:
        query += ' WHERE users.username LIKE ?'
        params.append(f'%{filter_user}%')
        
    # Сортировка по дате
    if sort_order == 'asc':
        query += ' ORDER BY posts.created_at ASC'
    else:
        query += ' ORDER BY posts.created_at DESC'
        
    posts = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template('index.html', posts=posts, filter_user=filter_user, sort_order=sort_order)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Регистрация нового пользователя."""
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        username = request.form.get('username').strip('@')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        use_2fa = 1 if request.form.get('use_2fa') else 0
        
        if password != confirm_password:
            flash('Пароли не совпадают!', 'danger')
            return redirect(url_for('register'))
            
        password_hash = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (nickname, username, password_hash, email, use_2fa) VALUES (?, ?, ?, ?, ?)',
                (nickname, username, password_hash, email, use_2fa)
            )
            conn.commit()
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Такой юзернейм уже занят!', 'danger')
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Шаг 1 входа: проверка логина и пароля."""
    if request.method == 'POST':
        username = request.form.get('username').strip('@')
        password = request.form.get('password')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            if user['use_2fa'] and user['email']:
                # Генерация кода 2FA
                code = generate_auth_code()
                # Удаляем старые коды для этого пользователя
                conn.execute('DELETE FROM auth_codes WHERE user_id = ?', (user['id'],))
                conn.execute(
                    'INSERT INTO auth_codes (user_id, code, attempts) VALUES (?, ?, 0)',
                    (user['id'], code)
                )
                conn.commit()
                conn.close()
                
                # Симуляция отправки кода (в продакшене здесь отправка на email)
                print(f"\n[2FA СИМУЛЯЦИЯ] Код для пользователя {user['username']}: {code}\n")
                
                session['pending_user_id'] = user['id']
                flash('На вашу почту отправлен разовый код подтверждения (проверьте консоль сервера).', 'info')
                return redirect(url_for('verify_2fa'))
            else:
                # Если 2FA выключена, сразу авторизуем
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['nickname'] = user['nickname']
                conn.close()
                flash('Вы успешно вошли в систему!', 'success')
                return redirect(url_for('index'))
        else:
            conn.close()
            flash('Неверный юзернейм или пароль.', 'danger')
            
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Шаг 2 входа: проверка разового кода (2FA) с лимитом 3 попытки."""
    user_id = session.get('pending_user_id')
    if not user_id:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    auth_record = conn.execute('SELECT * FROM auth_codes WHERE user_id = ?', (user_id,)).fetchone()
    
    if not auth_record:
        conn.close()
        flash('Код устарел или не запрашивался. Войдите заново.', 'danger')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        entered_code = request.form.get('code')
        
        if auth_record['attempts'] >= 3:
            conn.execute('DELETE FROM auth_codes WHERE user_id = ?', (user_id,))
            conn.commit()
            conn.close()
            session.pop('pending_user_id', None)
            flash('Превышено количество попыток (3 из 3). Код сброшен, запросите вход заново.', 'danger')
            return redirect(url_for('login'))
            
        if entered_code == auth_record['code']:
            # Успешный вход
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            conn.execute('DELETE FROM auth_codes WHERE user_id = ?', (user_id,))
            conn.commit()
            conn.close()
            
            session.pop('pending_user_id', None)
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nickname'] = user['nickname']
            
            # Оповещение о входе в аккаунт
            print(f"\n[ОПОВЕЩЕНИЕ БЕЗОПАСНОСТИ] В ваш аккаунт @{user['username']} выполнен успешный вход!\n")
            
            flash('Вход успешно подтвержден!', 'success')
            return redirect(url_for('index'))
        else:
            # Увеличиваем счетчик неудачных попыток
            new_attempts = auth_record['attempts'] + 1
            conn.execute('UPDATE auth_codes SET attempts = ? WHERE user_id = ?', (new_attempts, user_id))
            conn.commit()
            conn.close()
            
            remaining = 3 - new_attempts
            if remaining > 0:
                flash(f'Неверный код! Осталось попыток: {remaining}', 'danger')
            else:
                flash('Превышено количество попыток! Код сброшен.', 'danger')
                return redirect(url_for('login'))
                
    conn.close()
    return render_template('verify_2fa.html')

@app.route('/logout')
def logout():
    """Выход из аккаунта."""
    session.clear()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/create-post', methods=['GET', 'POST'])
def create_post():
    """Создание поста (доступно только авторизованным)."""
    if 'user_id' not in session:
        flash('Для создания поста необходимо войти в аккаунт.', 'warning')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        content = request.form.get('content')
        if content.strip():
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO posts (user_id, content) VALUES (?, ?)',
                (session['user_id'], content)
            )
            conn.commit()
            conn.close()
            flash('Пост успешно опубликован!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Пост не может быть пустым.', 'danger')
            
    return render_template('create_post.html')

@app.route('/profile')
def profile():
    """Отдельная страница профиля текущего пользователя."""
    if 'user_id' not in session:
        flash('Пожалуйста, войдите, чтобы просмотреть свой профиль.', 'warning')
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    user_id = session['user_id']
    
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    user_posts = conn.execute('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
    conn.close()
    
    return render_template('profile.html', user=user, posts=user_posts)

@app.route('/user/<username>')
def user_profile(username):
    """Просмотр профиля и постов любого пользователя по его юзернейму."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    
    if not user:
        conn.close()
        flash('Пользователь не найден.', 'danger')
        return redirect(url_for('index'))
        
    user_posts = conn.execute('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
    conn.close()
    
    return render_template('profile.html', user=user, posts=user_posts)

if __name__ == '__main__':
    # Запуск с поддержкой HTTPS (если папка certs и сертификаты существуют)
    # Для разработки можно сгенерировать самоподписанные сертификаты
    if os.path.exists(Config.SSL_CERT) and os.path.exists(Config.SSL_KEY):
        app.run(debug=True, host='0.0.0.0', port=5000, ssl_context=(Config.SSL_CERT, Config.SSL_KEY))
    else:
        print("Внимание: SSL-сертификаты не найдены в папке certs/. Запуск по обычному HTTP (для теста).")
        app.run(debug=True, host='0.0.0.0', port=5000)