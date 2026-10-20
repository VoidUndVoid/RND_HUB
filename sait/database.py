import sqlite3
import os

DB_NAME = 'database.db'

def get_db_connection():
    """Создает и возвращает соединение с базой данных SQLite."""
    conn = sqlite3.connect(DB_NAME)
    # Настраиваем, чтобы строки возвращались в виде словарей/объектов с доступом по имени колонок
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Инициализирует базу данных и создает необходимые таблицы."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Таблица пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            use_2fa BOOLEAN DEFAULT 0
        )
    ''')
    
    # 2. Таблица постов
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # 3. Таблица для управления 2FA (разовые коды и счетчик попыток)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            attempts INTEGER DEFAULT 0,
            expires_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("База данных SQLite и таблицы успешно созданы.")

if __name__ == '__main__':
    init_db()