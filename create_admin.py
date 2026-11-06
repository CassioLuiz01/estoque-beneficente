"""Cria um administrador pedindo os dados no terminal, sem deixar a senha gravada no código."""
import getpass
import os
import sqlite3

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.getenv('DATABASE', os.path.join(BASE_DIR, 'db.sqlite'))
TAMANHO_MINIMO_SENHA = 8


def main():
    username = input('Usuário: ').strip()
    full_name = input('Nome completo: ').strip()
    email = input('E-mail: ').strip()
    password = getpass.getpass('Senha: ')

    if not username or not full_name or not email:
        raise SystemExit('Preencha usuário, nome e e-mail.')
    if len(password) < TAMANHO_MINIMO_SENHA:
        raise SystemExit(f'A senha precisa ter pelo menos {TAMANHO_MINIMO_SENHA} caracteres.')
    if password != getpass.getpass('Confirme a senha: '):
        raise SystemExit('As senhas não conferem.')

    connection = sqlite3.connect(DATABASE)
    try:
        connection.execute(
            'INSERT INTO users (username, password, full_name, email, is_admin) VALUES (?, ?, ?, ?, 1)',
            (username, generate_password_hash(password, method='pbkdf2:sha256'), full_name, email),
        )
        connection.commit()
    except sqlite3.IntegrityError:
        raise SystemExit('Já existe uma conta com esse usuário ou e-mail.')
    finally:
        connection.close()
    print('Administrador criado.')


if __name__ == '__main__':
    main()
