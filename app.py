import hashlib
import logging
import os
import re
import secrets
import smtplib
import sqlite3
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
ASSETS_DIR = os.path.join(BASE_DIR, 'estoque-app', 'assets')
TAMANHO_MINIMO_SENHA = 8
QUANTIDADE_MAXIMA = 100_000
VALIDADE_TOKEN = timedelta(minutes=30)
TAMANHO_MAXIMO_TEXTO = 100
EMAIL_REGEX = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
# Hash fixo usado quando o usuário não existe, para o tempo de resposta não revelar quais usuários existem.
HASH_FICTICIO = generate_password_hash(secrets.token_urlsafe(16), method='pbkdf2:sha256')

logger = logging.getLogger(__name__)

secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise RuntimeError('Defina SECRET_KEY no arquivo .env (veja o .env.example).')

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'estoque-app', 'templates'),
    static_folder=os.path.join(BASE_DIR, 'estoque-app', 'static'),
)
app.config.update(
    SECRET_KEY=secret_key,
    DATABASE=os.getenv('DATABASE', os.path.join(BASE_DIR, 'db.sqlite')),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', '0') == '1',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=1024 * 1024,
)

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, storage_uri='memory://')


def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


@app.before_request
def carregar_usuario():
    """Busca o usuário no banco a cada requisição, para mudanças de permissão valerem na hora."""
    g.user = None
    user_id = session.get('user_id')
    if user_id is None:
        return
    conn = get_db_connection()
    g.user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if g.user is None:
        session.clear()


@app.after_request
def adicionar_cabecalhos_seguranca(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    # Evita que o token de redefinição de senha vaze pelo cabeçalho Referer.
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@app.errorhandler(403)
def acesso_negado(_erro):
    return render_template('403.html'), 403


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Faça login novamente.'}), 401
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        if not g.user['is_admin']:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def validar_item(tipo, tamanho, genero, quantidade):
    """Retorna (dados, erro). Quantidade precisa ser um inteiro entre 0 e o máximo permitido."""
    campos = [str(campo or '').strip() for campo in (tipo, tamanho, genero)]
    if not all(campos) or any(len(campo) > TAMANHO_MAXIMO_TEXTO for campo in campos):
        return None, f'Preencha tipo, tamanho e gênero com até {TAMANHO_MAXIMO_TEXTO} caracteres.'
    try:
        quantidade = int(quantidade)
    except (TypeError, ValueError):
        return None, 'A quantidade precisa ser um número inteiro.'
    if not 0 <= quantidade <= QUANTIDADE_MAXIMA:
        return None, f'A quantidade precisa estar entre 0 e {QUANTIDADE_MAXIMA}.'
    return (*campos, quantidade), None


def validar_usuario(full_name, email, password, senha_obrigatoria=True):
    if not full_name.strip() or len(full_name) > TAMANHO_MAXIMO_TEXTO:
        return 'Informe um nome válido.'
    if not EMAIL_REGEX.match(email) or len(email) > 254:
        return 'Informe um e-mail válido.'
    if (senha_obrigatoria or password) and len(password) < TAMANHO_MINIMO_SENHA:
        return f'A senha precisa ter pelo menos {TAMANHO_MINIMO_SENHA} caracteres.'
    return None


def gerar_hash_senha(password):
    return generate_password_hash(password, method='pbkdf2:sha256')


def hash_token(token):
    """Só o hash do token fica no banco: um vazamento do banco não permite redefinir senhas."""
    return hashlib.sha256(token.encode()).hexdigest()


def buscar_por_token(conn, token):
    """Retorna o usuário dono de um token válido e ainda dentro da validade."""
    agora = datetime.now(timezone.utc).isoformat()
    return conn.execute(
        'SELECT id FROM users WHERE reset_token = ? AND reset_token_expires > ?',
        (hash_token(token), agora),
    ).fetchone()


@app.route('/')
def home():
    if g.user:
        return redirect(url_for('index'))
    return render_template('home.html')


@app.route('/index')
@login_required
def index():
    first_name = g.user['full_name'].split()[0]
    session['first_name'] = first_name
    return render_template('index.html', first_name=first_name)


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per hour', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()

        erro = validar_usuario(full_name, email, password)
        if not username or len(username) > TAMANHO_MAXIMO_TEXTO:
            erro = 'Informe um usuário válido.'
        if erro:
            flash(erro)
            return redirect(url_for('register'))

        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (username, password, full_name, email) VALUES (?, ?, ?, ?)',
                (username, gerar_hash_senha(password), full_name, email),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash('Não foi possível concluir o cadastro. Tente outros dados.')
            return redirect(url_for('register'))
        finally:
            conn.close()

        flash('Cadastro realizado! Faça login para continuar.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('5 per minute', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        senha_correta = check_password_hash(user['password'] if user else HASH_FICTICIO, password)
        if user and senha_correta:
            # Limpa a sessão anterior para evitar fixação de sessão.
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            if user['is_admin']:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('index'))
        flash('Usuário ou senha incorretos.')

    return render_template('login.html')


@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, full_name, email, is_admin FROM users').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', users=users)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user is None:
        conn.close()
        abort(404)

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        is_admin = 1 if request.form.get('is_admin') else 0

        erro = validar_usuario(full_name, email, password, senha_obrigatoria=False)
        if not erro and user_id == g.user['id'] and not is_admin:
            erro = 'Você não pode remover o seu próprio acesso de administrador.'
        if erro:
            conn.close()
            flash(erro)
            return redirect(url_for('edit_user', user_id=user_id))

        hashed_password = gerar_hash_senha(password) if password else user['password']
        try:
            conn.execute(
                'UPDATE users SET full_name = ?, email = ?, password = ?, is_admin = ? WHERE id = ?',
                (full_name, email, hashed_password, is_admin, user_id),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash('Este e-mail já está em uso.')
            return redirect(url_for('edit_user', user_id=user_id))
        finally:
            conn.close()

        flash('Usuário atualizado.')
        return redirect(url_for('admin_dashboard'))

    conn.close()
    return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == g.user['id']:
        flash('Você não pode excluir a sua própria conta.')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    # Os itens do usuário são removidos junto (ON DELETE CASCADE).
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('Usuário excluído.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin_manage_estoque/<int:user_id>')
@admin_required
def admin_manage_estoque(user_id):
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM estoque WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return render_template('admin_manage_estoque.html', items=items, user_id=user_id)


@app.route('/admin_edit_item/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_item(id):
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM estoque WHERE id = ?', (id,)).fetchone()
    if item is None:
        conn.close()
        abort(404)

    if request.method == 'POST':
        dados, erro = validar_item(
            request.form.get('tipo'), request.form.get('tamanho'),
            request.form.get('genero'), request.form.get('quantidade'),
        )
        if erro:
            conn.close()
            flash(erro)
            return redirect(url_for('admin_edit_item', id=id))

        conn.execute(
            'UPDATE estoque SET tipo = ?, tamanho = ?, genero = ?, quantidade = ? WHERE id = ?',
            (*dados, id),
        )
        conn.commit()
        conn.close()

        flash('Item atualizado com sucesso.')
        return redirect(url_for('admin_manage_estoque', user_id=item['user_id']))

    conn.close()
    return render_template('admin_edit_item.html', item=item)


@app.route('/admin_remove_item/<int:id>', methods=['POST'])
@admin_required
def admin_remove_item(id):
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM estoque WHERE id = ?', (id,)).fetchone()
    if item is None:
        conn.close()
        abort(404)
    conn.execute('DELETE FROM estoque WHERE id = ?', (id,))
    conn.commit()
    conn.close()

    flash('Item removido com sucesso.')
    return redirect(url_for('admin_manage_estoque', user_id=item['user_id']))


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        erro = validar_usuario(full_name, email, password, senha_obrigatoria=False)
        if erro:
            flash(erro)
            return redirect(url_for('edit_profile'))

        hashed_password = gerar_hash_senha(password) if password else g.user['password']
        conn = get_db_connection()
        try:
            conn.execute(
                'UPDATE users SET full_name = ?, email = ?, password = ? WHERE id = ?',
                (full_name, email, hashed_password, g.user['id']),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash('Este e-mail já está em uso.')
            return redirect(url_for('edit_profile'))
        finally:
            conn.close()

        flash('Perfil atualizado.')
        return redirect(url_for('index'))

    return render_template('edit_profile.html', user=g.user)


@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit('5 per hour', methods=['POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        conn = get_db_connection()
        user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if user:
            token = secrets.token_urlsafe(32)
            expira = (datetime.now(timezone.utc) + VALIDADE_TOKEN).isoformat()
            conn.execute(
                'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
                (hash_token(token), expira, user['id']),
            )
            conn.commit()
            send_recovery_email(email, token)
        conn.close()

        # A mesma mensagem nos dois casos: a tela não revela quais e-mails estão cadastrados.
        flash('Se o e-mail estiver cadastrado, enviaremos um link de recuperação.')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


def send_recovery_email(email, token):
    sender_email = os.getenv('SMTP_USER')
    sender_password = os.getenv('SMTP_PASSWORD')
    if not sender_email or not sender_password:
        logger.warning('SMTP não configurado: e-mail de recuperação não enviado.')
        return

    recovery_url = url_for('reset_password', token=token, _external=True)
    msg = MIMEText(
        f'Use este link para redefinir sua senha. Ele vale por 30 minutos: {recovery_url}',
        'plain',
        'utf-8',
    )
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = 'Recuperação de senha - Estoque Beneficente'

    try:
        host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        port = int(os.getenv('SMTP_PORT', '587'))
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
    except (smtplib.SMTPException, OSError):
        logger.exception('Falha ao enviar o e-mail de recuperação.')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit('10 per hour', methods=['POST'])
def reset_password(token):
    conn = get_db_connection()
    user = buscar_por_token(conn, token)
    if user is None:
        conn.close()
        flash('Link inválido ou expirado.')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        if len(new_password) < TAMANHO_MINIMO_SENHA:
            conn.close()
            flash(f'A senha precisa ter pelo menos {TAMANHO_MINIMO_SENHA} caracteres.')
            return redirect(url_for('reset_password', token=token))

        # O token é apagado junto com a troca da senha, então só funciona uma vez.
        conn.execute(
            'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
            (gerar_hash_senha(new_password), user['id']),
        )
        conn.commit()
        conn.close()
        session.clear()
        flash('Senha redefinida. Faça login.')
        return redirect(url_for('login'))

    conn.close()
    return render_template('reset_password.html', token=token)


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/novo_estoque', methods=['GET', 'POST'])
@login_required
def novo_estoque():
    first_name = session.get('first_name', 'Usuário')

    if request.method == 'POST':
        dados, erro = validar_item(
            request.form.get('tipo'), request.form.get('tamanho'),
            request.form.get('genero'), request.form.get('quantidade'),
        )
        if erro:
            flash(erro)
            return redirect(url_for('novo_estoque'))

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO estoque (tipo, tamanho, genero, quantidade, user_id) VALUES (?, ?, ?, ?, ?)',
            (*dados, g.user['id']),
        )
        conn.commit()
        conn.close()
        return render_template(
            'novo_estoque.html', mensagem='Item adicionado com sucesso!', first_name=first_name,
        )

    return render_template('novo_estoque.html', first_name=first_name)


@app.route('/gerenciar_estoque')
@login_required
def gerenciar_estoque():
    first_name = session.get('first_name', 'Usuário')
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM estoque WHERE user_id = ?', (g.user['id'],)).fetchall()
    conn.close()
    return render_template('gerenciar_estoque.html', items=items, first_name=first_name)


@app.route('/ajuda')
def ajuda():
    first_name = session.get('first_name', 'Usuário')
    return render_template('ajuda.html', first_name=first_name)


@app.route('/quem_somos')
def quem_somos():
    first_name = session.get('first_name', 'Usuário')
    return render_template('quem_somos.html', first_name=first_name)


@app.route('/remove_item/<int:id>', methods=['POST'])
@login_required
def remove_item(id):
    conn = get_db_connection()
    cursor = conn.execute('DELETE FROM estoque WHERE id = ? AND user_id = ?', (id, g.user['id']))
    conn.commit()
    conn.close()
    if cursor.rowcount == 0:
        return jsonify({'success': False}), 404
    return jsonify({'success': True})


@app.route('/edit_item/<int:id>', methods=['POST'])
@login_required
def edit_item(id):
    data = request.get_json(silent=True) or {}
    dados, erro = validar_item(
        data.get('tipo'), data.get('tamanho'), data.get('genero'), data.get('quantidade'),
    )
    if erro:
        return jsonify({'success': False, 'error': erro}), 400

    conn = get_db_connection()
    cursor = conn.execute(
        'UPDATE estoque SET tipo = ?, tamanho = ?, genero = ?, quantidade = ? WHERE id = ? AND user_id = ?',
        (*dados, id, g.user['id']),
    )
    conn.commit()
    conn.close()
    if cursor.rowcount == 0:
        return jsonify({'success': False}), 404
    return jsonify({'success': True})


@app.route('/assets/images/<path:filename>')
def custom_static(filename):
    return send_from_directory(os.path.join(ASSETS_DIR, 'images'), filename)


if __name__ == '__main__':
    # O modo debug permite executar código pelo navegador, então fica desligado por padrão.
    app.run(debug=os.getenv('FLASK_DEBUG', '0') == '1')
