"""Testes das correções descritas em docs/relatorio-seguranca.md."""
import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ['SECRET_KEY'] = 'chave-usada-apenas-nos-testes'

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

import app as modulo  # noqa: E402

SENHA = 'senha-de-teste-123'


@pytest.fixture
def banco(tmp_path):
    caminho = tmp_path / 'teste.sqlite'
    conn = sqlite3.connect(caminho)
    conn.executescript((RAIZ / 'schema.sql').read_text(encoding='utf-8'))
    hash_senha = modulo.gerar_hash_senha(SENHA)
    conn.executemany(
        'INSERT INTO users (id, username, password, full_name, email, is_admin) VALUES (?, ?, ?, ?, ?, ?)',
        [
            (1, 'admin', hash_senha, 'Admin Teste', 'admin@exemplo.com', 1),
            (2, 'ana', hash_senha, 'Ana Teste', 'ana@exemplo.com', 0),
            (3, 'bia', hash_senha, 'Bia Teste', 'bia@exemplo.com', 0),
        ],
    )
    conn.execute(
        "INSERT INTO estoque (id, tipo, tamanho, genero, quantidade, user_id) VALUES (1, 'Camisa', 'M', 'Unissex', 5, 3)"
    )
    conn.commit()
    conn.close()
    modulo.app.config.update(DATABASE=str(caminho), TESTING=True, WTF_CSRF_ENABLED=False)
    modulo.limiter.enabled = False
    yield caminho
    modulo.app.config['WTF_CSRF_ENABLED'] = True


@pytest.fixture
def cliente(banco):
    return modulo.app.test_client()


def entrar(cliente, usuario):
    return cliente.post('/login', data={'username': usuario, 'password': SENHA})


def consultar(banco, sql, *parametros):
    conn = sqlite3.connect(banco)
    linha = conn.execute(sql, parametros).fetchone()
    conn.close()
    return linha


def test_app_nao_inicia_sem_secret_key():
    ambiente = {k: v for k, v in os.environ.items() if k != 'SECRET_KEY'}
    resultado = subprocess.run(
        [sys.executable, '-c', 'import dotenv; dotenv.load_dotenv = lambda *a, **k: None; import app'],
        cwd=RAIZ, env=ambiente, capture_output=True, text=True,
    )
    assert resultado.returncode != 0
    assert 'SECRET_KEY' in resultado.stderr


def test_post_sem_token_csrf_e_rejeitado(cliente):
    modulo.app.config['WTF_CSRF_ENABLED'] = True
    resposta = cliente.post('/login', data={'username': 'ana', 'password': SENHA})
    assert resposta.status_code == 400


def test_post_com_token_csrf_e_aceito(cliente):
    modulo.app.config['WTF_CSRF_ENABLED'] = True
    pagina = cliente.get('/login').get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', pagina).group(1)
    resposta = cliente.post('/login', data={'username': 'ana', 'password': SENHA, 'csrf_token': token})
    assert resposta.status_code == 302


def test_login_e_limitado_apos_tentativas(cliente):
    modulo.limiter.enabled = True
    modulo.limiter.reset()
    codigos = [
        cliente.post('/login', data={'username': 'ana', 'password': 'errada'}).status_code
        for _ in range(6)
    ]
    modulo.limiter.reset()
    assert codigos[:5] == [200] * 5
    assert codigos[5] == 429


def test_usuario_comum_nao_acessa_area_admin(cliente):
    entrar(cliente, 'ana')
    assert cliente.get('/admin_dashboard').status_code == 403
    assert cliente.post('/delete_user/3').status_code == 403
    assert consultar(modulo.app.config['DATABASE'], 'SELECT id FROM users WHERE id = 3') is not None


def test_visitante_e_enviado_para_login_na_area_admin(cliente):
    resposta = cliente.get('/admin_dashboard')
    assert resposta.status_code == 302
    assert '/login' in resposta.location


def test_permissao_removida_vale_na_hora(cliente, banco):
    entrar(cliente, 'admin')
    assert cliente.get('/admin_dashboard').status_code == 200
    conn = sqlite3.connect(banco)
    conn.execute('UPDATE users SET is_admin = 0 WHERE id = 1')
    conn.commit()
    conn.close()
    assert cliente.get('/admin_dashboard').status_code == 403


def test_usuario_nao_altera_item_de_outro_usuario(cliente, banco):
    entrar(cliente, 'ana')
    dados = {'tipo': 'Calça', 'tamanho': 'G', 'genero': 'Unissex', 'quantidade': 1}
    assert cliente.post('/edit_item/1', json=dados).status_code == 404
    assert cliente.post('/remove_item/1').status_code == 404
    assert consultar(banco, 'SELECT tipo FROM estoque WHERE id = 1') == ('Camisa',)


@pytest.mark.parametrize('quantidade', [-1, 'abc', None, 100_001])
def test_quantidade_invalida_e_rejeitada(cliente, banco, quantidade):
    entrar(cliente, 'bia')
    dados = {'tipo': 'Calça', 'tamanho': 'G', 'genero': 'Unissex', 'quantidade': quantidade}
    assert cliente.post('/edit_item/1', json=dados).status_code == 400
    assert consultar(banco, 'SELECT quantidade FROM estoque WHERE id = 1') == (5,)


def test_senha_curta_e_rejeitada_no_cadastro(cliente, banco):
    cliente.post('/register', data={
        'username': 'novo', 'password': 'curta', 'full_name': 'Novo', 'email': 'novo@exemplo.com',
    })
    assert consultar(banco, "SELECT id FROM users WHERE username = 'novo'") is None


def test_esqueci_senha_nao_revela_quais_emails_existem(cliente):
    existente = cliente.post('/forgot_password', data={'email': 'ana@exemplo.com'}, follow_redirects=True)
    inexistente = cliente.post('/forgot_password', data={'email': 'nao@exemplo.com'}, follow_redirects=True)
    mensagem = 'Se o e-mail estiver cadastrado'
    assert mensagem in existente.get_data(as_text=True)
    assert mensagem in inexistente.get_data(as_text=True)


def definir_token(banco, token, expira):
    conn = sqlite3.connect(banco)
    conn.execute(
        'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = 2',
        (modulo.hash_token(token), expira.isoformat()),
    )
    conn.commit()
    conn.close()


def test_token_de_redefinicao_fica_so_como_hash(cliente, banco, monkeypatch):
    enviados = []
    monkeypatch.setattr(modulo, 'send_recovery_email', lambda email, token: enviados.append(token))
    cliente.post('/forgot_password', data={'email': 'ana@exemplo.com'})
    guardado = consultar(banco, 'SELECT reset_token FROM users WHERE id = 2')[0]
    assert enviados and guardado != enviados[0]
    assert guardado == modulo.hash_token(enviados[0])


def test_token_funciona_uma_unica_vez(cliente, banco):
    definir_token(banco, 'token-valido', datetime.now(timezone.utc) + timedelta(minutes=5))
    nova = {'new_password': 'outra-senha-segura'}
    assert '/login' in cliente.post('/reset_password/token-valido', data=nova).location
    assert '/forgot_password' in cliente.post('/reset_password/token-valido', data=nova).location


def test_token_expirado_e_rejeitado(cliente, banco):
    definir_token(banco, 'token-velho', datetime.now(timezone.utc) - timedelta(minutes=1))
    resposta = cliente.post('/reset_password/token-velho', data={'new_password': 'outra-senha-segura'})
    assert '/forgot_password' in resposta.location
    assert consultar(banco, 'SELECT reset_token FROM users WHERE id = 2') is not None


def test_logout_nao_aceita_get(cliente):
    entrar(cliente, 'ana')
    assert cliente.get('/logout').status_code == 405
    assert cliente.get('/index').status_code == 200
    assert cliente.post('/logout').status_code == 302
    assert cliente.get('/index').status_code == 302


def test_cabecalhos_de_seguranca(cliente):
    cabecalhos = cliente.get('/').headers
    assert cabecalhos['X-Frame-Options'] == 'DENY'
    assert cabecalhos['X-Content-Type-Options'] == 'nosniff'
    assert cabecalhos['Referrer-Policy'] == 'no-referrer'
    assert "frame-ancestors 'none'" in cabecalhos['Content-Security-Policy']


def test_debug_fica_desligado_por_padrao():
    assert modulo.app.debug is False
    assert "os.getenv('FLASK_DEBUG', '0') == '1'" in (RAIZ / 'app.py').read_text(encoding='utf-8')
