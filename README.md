# 🔐 Sistema de Autenticação e Banco de Dados Seguro

Este projeto conta com uma interface moderna e responsiva de login/cadastro integrada a um banco de dados **SQLite** seguro e uma API em **Node.js** com zero dependências externas obrigatórias.

---

## 🚀 Como Iniciar

Abra o terminal na pasta do projeto e execute:

```bash
node server.js
```

Ou via npm:

```bash
npm start
```

Depois, acesse no seu navegador: **[http://localhost:3000](http://localhost:3000)**.

---

## 🛡️ Pilares de Segurança Implementados

### 1. Hashing Criptográfico com `scrypt` e Salt Único
- **Nunca salvamos senhas em texto puro**.
- Utilizamos o algoritmo **`scrypt`** (módulo nativo `node:crypto`), padrão recomendado pela **OWASP** e **NIST**.
- Cada senha possui um **Salt criptográfico exclusivo de 16 bytes (128 bits)** gerado aleatoriamente (`crypto.randomBytes`). Isso anula ataques de Rainbow Tables.
- O formato armazenado no banco é `salt:hash`.

### 2. Prevenção Contra Timing Attacks (`crypto.timingSafeEqual`)
- Ao validar a senha informada contra o hash armazenado, a comparação de bytes é feita com tempo constante (`timingSafeEqual`), evitando que invasores deduzam a senha medindo variações em nanossegundos na resposta do servidor.

### 3. Proteção Total Contra Injeção de SQL (SQL Injection)
- Todas as operações no banco utilizam **Consultas Preparadas (`Prepared Statements`)** via `node:sqlite`.
- Os parâmetros enviados pelo usuário (`email`, `password`) são passados isolados do comando SQL, impedindo qualquer manipulação de queries maliciosas.

### 4. Proteção Contra Ataques de Força Bruta (Brute-Force Lockout)
- O banco registra as tentativas incorretas (`failed_attempts`).
- Ao atingir 5 tentativas incorretas consecutivas, a conta é **automaticamente bloqueada temporariamente por 15 minutos** (`locked_until`).
- Tentativas durante o bloqueio recebem código HTTP `423 Locked`.
- Ao efetuar o login com sucesso, o contador é zerado.

### 5. Defesa Contra Enumeração de Usuários
- Caso um invasor tente testar se um e-mail existe no sistema, o servidor simula o cálculo de hash para manter o tempo de resposta consistente antes de retornar `401 Unauthorized`.

---

## 🗄️ Estrutura do Banco de Dados (`schema.sql`)

O banco utiliza **SQLite (`users.db`)** no modo **WAL (Write-Ahead Logging)**:

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## 📁 Estrutura de Arquivos

- [index.html](file:///c:/Users/Denilson/OneDrive/Documentos/projetosGITHUB/HTML,CSS,JavaScript/tela-de-login/index.html): Interface semântica de login e cadastro.
- [style.css](file:///c:/Users/Denilson/OneDrive/Documentos/projetosGITHUB/HTML,CSS,JavaScript/tela-de-login/style.css): Estilos CSS modernos com suporte a Dark Mode e acessibilidade.
- [script.js](file:///c:/Users/Denilson/OneDrive/Documentos/projetosGITHUB/HTML,CSS,JavaScript/tela-de-login/script.js): Lógica de alternância (Login/Cadastro), feedback e comunicação com a API.
- [dashboard.html](file:///c:/Users/Denilson/OneDrive/Documentos/projetosGITHUB/HTML,CSS,JavaScript/tela-de-login/dashboard.html): Página interna restrita (área do usuário autenticado).
- [dashboard.css](file:///c:/Users/Denilson/OneDrive/Documentos/projetosGITHUB/HTML,CSS,JavaScript/tela-de-login/dashboard.css): Estilos visuais do painel, cards de métricas e navbar.
- [dashboard.js](file:///c:/Users/Denilson/OneDrive/Documentos/projetosGITHUB/HTML,CSS,JavaScript/tela-de-login/dashboard.js): Guarda de autenticação, verificação de sessão e logout.
- [database.js](file:///c:/Users/Denilson/OneDrive/Documentos/projetosGITHUB/HTML,CSS,JavaScript/tela-de-login/database.js): Conexão com SQLite nativo e queries preparadas.
- [auth.js](file:///c:/Users/Denilson/OneDrive/Documentos/projetosGITHUB/HTML,CSS,JavaScript/tela-de-login/auth.js): Hashing criptográfico `scrypt`, salts e `timingSafeEqual`.
- [server.js](file:///c:/Users/Denilson/OneDrive/Documentos/projetosGITHUB/HTML,CSS,JavaScript/tela-de-login/server.js): Servidor HTTP e endpoints REST (`/api/register`, `/api/login`, `/api/me`, `/api/logout`).
- [schema.sql](file:///c:/Users/Denilson/OneDrive/Documentos/projetosGITHUB/HTML,CSS,JavaScript/tela-de-login/schema.sql): Script DDL da estrutura das tabelas.
- [tests/](file:///c:/Users/Denilson/OneDrive/Documentos/projetosGITHUB/HTML,CSS,JavaScript/tela-de-login/tests/): Suíte com 23 testes automatizados (unitários e integração).
