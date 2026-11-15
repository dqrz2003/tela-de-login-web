-- ============================================================================
-- SCHEMA DO BANCO DE DADOS: GERENCIAMENTO SEGURO DE USUÁRIOS (SQLite / SQL ANSI)
-- ============================================================================

-- Tabela de Usuários com hashing de senha e proteção contra força bruta
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE, -- Case-insensitive para evitar duplicatas por caixa alta/baixa
    password_hash TEXT NOT NULL,               -- Hash derivado com scrypt + salt criptográfico (nunca texto puro)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    failed_attempts INTEGER DEFAULT 0,         -- Contador de tentativas incorretas
    locked_until DATETIME NULL                 -- Bloqueio temporário após sucessivos erros (anti força bruta)
);

-- Índice no e-mail para buscas rápidas com unicidade garantida
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Tabela de Sessões / Tokens de Acesso
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,                       -- Token seguro (ex: UUID ou 32 bytes hex)
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Índice para expiração de sessões
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
