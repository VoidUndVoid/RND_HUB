import os

class Config:
    # Секретный ключ для подписи сессий (в продакшене лучше менять на случайную строку)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-key-change-it-in-production'
    
    # Путь к файлу базы данных SQLite
    DATABASE = 'database.db'
    
    # Пути к SSL/TLS сертификатам для работы по HTTPS
    SSL_CERT = 'certs/cert.pem'
    SSL_KEY = 'certs/key.pem'