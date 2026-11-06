# Relatório de segurança: Estoque Beneficente

## Resumo

Revisão do código de um projeto acadêmico em Flask e SQLite, feita por leitura do código e confirmada com testes automatizados. O objetivo foi encontrar falhas, avaliar o risco e corrigi-las nesta versão.

- **Escopo:** código da aplicação, templates, configuração e arquivos do repositório original.
- **Fora do escopo:** teste de invasão, servidor de hospedagem e dependências de terceiros.
- **Dados:** nenhuma senha ou dado pessoal do projeto original é reproduzido neste documento.

A classificação de severidade é uma avaliação qualitativa, considerando o sistema publicado na internet. A referência OWASP é o Top 10 de 2021.

## Pontos positivos do projeto original

- Senhas guardadas com hash (`pbkdf2:sha256`), não em texto puro.
- Consultas SQL com parâmetros, o que reduz o risco de SQL Injection.
- Usuários comuns só alteram os próprios itens (`AND user_id = ?`).

## Vulnerabilidades e correções

### 1. Chave de sessão fixa no código: crítica

- **OWASP:** A02 Cryptographic Failures / A07 Identification and Authentication Failures
- **Risco:** a chave assina o cookie de sessão. Quem a conhece pode forjar uma sessão de qualquer usuário, inclusive de administrador.
- **Correção:** a chave vem da variável `SECRET_KEY`, e o sistema não inicia sem ela.

### 2. Modo debug sempre ligado: crítica

- **OWASP:** A05 Security Misconfiguration
- **Risco:** o depurador do Werkzeug mostra detalhes internos e pode permitir a execução de código no servidor.
- **Correção:** o debug só liga com `FLASK_DEBUG=1`.

### 3. Senha e banco de dados no repositório: alta

- **OWASP:** A05 Security Misconfiguration / A07
- **Risco:** um script trazia a senha de um administrador, e o `db.sqlite` expunha contas, e-mails e hashes de senha.
- **Correção:** `create_admin.py` pede os dados no terminal, `.gitignore` bloqueia bancos e `.env`, e esta versão começa sem o histórico antigo. Apagar um arquivo não o remove do histórico do Git.

### 4. Sem proteção contra CSRF: alta

- **OWASP:** A01 Broken Access Control
- **Risco:** um site malicioso poderia fazer o navegador de uma pessoa logada executar ações, como excluir usuários ou itens.
- **Correção:** `Flask-WTF` exige um token em todo `POST`, incluindo as chamadas em JavaScript, e o cookie usa `SameSite=Lax`. A saída da conta agora só aceita `POST`.

### 5. Recuperação de senha frágil: alta

- **OWASP:** A07 Identification and Authentication Failures
- **Risco:** o token não expirava, continuava válido depois do uso e ficava legível no banco.
- **Correção:** token aleatório com `secrets`, validade de 30 minutos, uso único e apenas o hash SHA-256 salvo. A política `Referrer-Policy: no-referrer` evita o vazamento do link.

### 6. Tentativas de login ilimitadas: média

- **OWASP:** A07 Identification and Authentication Failures
- **Risco:** permitia testar senhas em grande quantidade.
- **Correção:** `Flask-Limiter` limita o login a 5 tentativas por minuto, e também limita cadastro e recuperação de senha. As senhas passam a ter no mínimo 8 caracteres.

### 7. Descoberta de contas cadastradas: média

- **OWASP:** A07 Identification and Authentication Failures
- **Risco:** a tela informava se um e-mail existia, e o tempo de resposta do login podia indicar se um usuário existia.
- **Correção:** a recuperação de senha mostra sempre a mesma mensagem, e o login faz a verificação de hash mesmo para usuário inexistente.

### 8. Permissões guardadas na sessão: média

- **OWASP:** A01 Broken Access Control
- **Risco:** quem perdesse o acesso de administrador continuava com ele até sair da conta. As rotas de administrador também apontavam para uma página inexistente, causando erro 500.
- **Correção:** os decoradores `login_required` e `admin_required` consultam o banco a cada requisição, e usuários sem permissão recebem erro 403. A sessão é limpa no login para evitar fixação de sessão.

### 9. Falta de validação de dados: média

- **OWASP:** A03 Injection / A04 Insecure Design
- **Risco:** o servidor aceitava quantidades negativas ou não numéricas, campos vazios e e-mails inválidos, e dados inesperados geravam erro 500.
- **Correção:** validação no servidor e restrição `CHECK (quantidade >= 0)` em novos bancos.

### 10. Configurações de navegador ausentes: baixa

- **OWASP:** A05 Security Misconfiguration
- **Risco:** menos proteção contra clickjacking e outros ataques no navegador.
- **Correção:** cabeçalhos `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` e cookie `HttpOnly`. Para HTTPS, há a opção `SESSION_COOKIE_SECURE=1`.

## Outras melhorias

- As mensagens do sistema, que nunca apareciam nas telas, agora são exibidas.
- O `schema.sql` não apaga mais as tabelas ao ser executado.
- Excluir um usuário remove os itens dele, e um administrador não pode excluir a própria conta nem retirar o próprio acesso.
- Credenciais de e-mail saíram do código e foram para o `.env`.

## Como foi verificado

- `tests/test_seguranca.py` traz 20 testes para as correções acima, todos aprovados.
- O fluxo de cadastro, login, inclusão, edição, remoção e saída foi usado em um navegador real, com banco temporário.
- O envio real de e-mail não foi testado, pois exige uma conta SMTP.

## Limitações e próximos passos

- **CSP:** ainda permite `unsafe-inline`, porque as telas usam `onclick` e estilos inline. O próximo passo é mover esse código para arquivos.
- **Limite de tentativas:** fica em memória e é zerado ao reiniciar. Em produção, o ideal é usar Redis e confirmar o IP real atrás de proxy.
- **Dependências:** as versões têm faixas, sem travar cada pacote. O próximo passo é gerar um arquivo travado e checar com `pip-audit`.
- **Conta:** não há verificação de e-mail nem autenticação em dois fatores.
- **Banco existente:** bancos criados com o esquema antigo precisam ser recriados ou migrados.
- **Alcance:** esta revisão não garante a ausência de outras falhas.
