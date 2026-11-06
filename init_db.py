"""Cria as tabelas do banco. Pode ser executado de novo sem apagar os dados."""
import os
import sqlite3

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.getenv('DATABASE', os.path.join(BASE_DIR, 'db.sqlite'))


def main():
    connection = sqlite3.connect(DATABASE)
    with open(os.path.join(BASE_DIR, 'schema.sql'), encoding='utf-8') as schema:
        connection.executescript(schema.read())
    connection.commit()
    connection.close()
    print(f'Banco pronto em {DATABASE}')


if __name__ == '__main__':
    main()
