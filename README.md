# Estoque Beneficente

Sistema web para organizar as doações de roupas de campanhas beneficentes: cada pessoa cadastra e controla o próprio estoque, informando tipo, tamanho, gênero e quantidade.

Esta é uma versão revisada de um projeto acadêmico feito em equipe, com foco em segurança. As vulnerabilidades encontradas, os riscos e as correções estão no [relatório de segurança](docs/relatorio-seguranca.md).

## Funcionalidades

- Cadastro, login e edição de perfil
- Recuperação de senha por e-mail, com link de uso único e validade de 30 minutos
- Cadastro, edição e remoção de itens, com estoque individual por usuário
- Área de administrador para gerenciar usuários e estoques

## Tecnologias

Python, Flask, SQLite, HTML, CSS, JavaScript e pytest.

## O que mudou em relação ao projeto original

| Área | Antes | Agora |
|---|---|---|
| Chave da sessão | Fixa no código | Lida do `.env`; o sistema não inicia sem ela |
| Modo debug | Sempre ligado | Desligado por padrão |
| Administrador | Senha gravada em um script | Criado no terminal, sem senha no código |
| Banco de dados | Enviado ao repositório | Fora do Git |
| Formulários | Sem proteção contra CSRF | Token CSRF em todas as ações |
| Login | Tentativas ilimitadas | Limite de tentativas por minuto |
| Recuperação de senha | Token sem validade e reutilizável | Token com validade, de uso único e guardado como hash |
| Testes | Nenhum | 20 testes automatizados de segurança |

## Como rodar

Requisito: Python 3.10 ou mais recente. Os comandos abaixo são para o Git Bash no Windows.

```bash
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
cp .env.example .env
```

Gere uma chave e coloque em `SECRET_KEY`, no arquivo `.env`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Crie o banco e, se precisar, um administrador:

```bash
python init_db.py
python create_admin.py
```

Inicie o sistema e acesse <http://127.0.0.1:5000>:

```bash
flask --app app run
```

## Testes

```bash
python -m pytest
```

## Limitações conhecidas

Este projeto é uma demonstração acadêmica. As limitações estão detalhadas no [relatório](docs/relatorio-seguranca.md#limitações-e-próximos-passos), entre elas a política de conteúdo que ainda permite scripts inline e o limite de tentativas guardado em memória.

## Autores

Projeto original, desenvolvido em equipe na faculdade:

- Cássio Luiz
- Ester Gonçalves
- Lucas de Freitas
- Petry Estevam
- Richard Gabriel

Cássio Luiz participou de diferentes etapas do projeto, junto com a equipe, e fez a apresentação em sala.

Repositório original: [Richardtidi/ProjetoInterdisciplinarI](https://github.com/Richardtidi/ProjetoInterdisciplinarI)

Revisão de segurança desta versão: Cássio Luiz, com apoio de IA (Claude).
