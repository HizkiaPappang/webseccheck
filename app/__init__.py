from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os
import pymysql
import time

pymysql.install_as_MySQLdb()

db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__, instance_relative_config=True)

    os.makedirs(app.instance_path, exist_ok=True)

    app.config['SECRET_KEY'] = os.getenv(
        'SECRET_KEY',
        'websec_checker_secret_key_dev'
    )

    database_url = os.getenv('DATABASE_URL')

    if database_url:
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    else:
        db_host = os.getenv('DB_HOST')
        db_user = os.getenv('DB_USER')
        db_name = os.getenv('DB_NAME')
        db_pass = os.getenv('DB_PASS', '')

        if db_host and db_user and db_name:
            if db_pass:
                app.config['SQLALCHEMY_DATABASE_URI'] = (
                    f"mysql+pymysql://{db_user}:{db_pass}@{db_host}/{db_name}"
                )
            else:
                app.config['SQLALCHEMY_DATABASE_URI'] = (
                    f"mysql+pymysql://{db_user}@{db_host}/{db_name}"
                )
        else:
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///websec.db'

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Silakan login terlebih dahulu.'
    login_manager.login_message_category = 'warning'

    # WAJIB: import models sebelum db.create_all()
    from app.models import User, ScanHistory
    from app.routes import main

    app.register_blueprint(main)

    with app.app_context():
        connected = False

        for i in range(10):
            try:
                db.create_all()
                connected = True
                print("Database siap digunakan dan tabel berhasil dibuat/diperbarui.")
                break
            except Exception as e:
                print(f"Mencoba koneksi database... ({i + 1}/10)")
                print(e)
                time.sleep(5)

        if not connected:
            print("Gagal terhubung ke database.")

    return app