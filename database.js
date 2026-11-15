// ============================================================================
// GERENCIADOR DO BANCO DE DADOS (database.js)
// Utiliza node:sqlite (nativo do Node.js v22+)
// ============================================================================
const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');

// Caminho do arquivo do banco SQLite
const DB_PATH = path.join(__dirname, 'users.db');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

// Instancia conexão com o banco de dados local
const db = new DatabaseSync(DB_PATH);

// Habilita chaves estrangeiras (Foreign Keys) e modo WAL para melhor performance
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA journal_mode = WAL;');

// Inicializa as tabelas a partir do schema.sql se ainda não existirem
function initializeDatabase() {
  if (fs.existsSync(SCHEMA_PATH)) {
    const schemaSql = fs.readFileSync(SCHEMA_PATH, 'utf-8');
    db.exec(schemaSql);
  }
}

initializeDatabase();

// ============================================================================
// CONSULTAS PREPARADAS (PREPARED STATEMENTS) - PROTEÇÃO CONTRA SQL INJECTION
// ============================================================================
const stmtInsertUser = db.prepare(`
  INSERT INTO users (email, password_hash)
  VALUES (?, ?)
`);

const stmtGetUserByEmail = db.prepare(`
  SELECT id, email, password_hash, failed_attempts, locked_until, created_at
  FROM users
  WHERE email = ?
`);

const stmtIncrementFailed = db.prepare(`
  UPDATE users
  SET failed_attempts = failed_attempts + 1,
      locked_until = CASE 
        WHEN failed_attempts + 1 >= 5 THEN datetime('now', '+15 minutes')
        ELSE NULL
      END,
      updated_at = CURRENT_TIMESTAMP
  WHERE id = ?
`);

const stmtResetFailed = db.prepare(`
  UPDATE users
  SET failed_attempts = 0,
      locked_until = NULL,
      updated_at = CURRENT_TIMESTAMP
  WHERE id = ?
`);

const stmtInsertSession = db.prepare(`
  INSERT INTO sessions (id, user_id, expires_at)
  VALUES (?, ?, datetime('now', ?))
`);

const stmtGetSession = db.prepare(`
  SELECT s.id, s.user_id, s.expires_at, u.email, u.created_at
  FROM sessions s
  JOIN users u ON u.id = s.user_id
  WHERE s.id = ? AND s.expires_at > datetime('now')
`);

const stmtDeleteSession = db.prepare(`
  DELETE FROM sessions WHERE id = ?
`);

// ============================================================================
// MÉTODOS PÚBLICOS SEGUROS
// ============================================================================

/**
 * Cria um novo usuário de forma segura.
 * @param {string} email
 * @param {string} passwordHash
 * @returns {number} ID do usuário criado
 */
function createUser(email, passwordHash) {
  const result = stmtInsertUser.run(email, passwordHash);
  return Number(result.lastInsertRowid);
}

/**
 * Localiza usuário pelo e-mail.
 * @param {string} email
 * @returns {object|null}
 */
function getUserByEmail(email) {
  return stmtGetUserByEmail.get(email) || null;
}

/**
 * Registra tentativa falha e aplica bloqueio temporário se atingir 5 erros.
 * @param {number} userId
 */
function recordFailedAttempt(userId) {
  stmtIncrementFailed.run(userId);
}

/**
 * Reseta o contador de tentativas falhas ao autenticar com sucesso.
 * @param {number} userId
 */
function resetFailedAttempts(userId) {
  stmtResetFailed.run(userId);
}

/**
 * Salva uma nova sessão no banco de dados.
 * @param {number} userId
 * @param {string} sessionToken
 * @param {number} hoursValid (padrão: 24 horas)
 */
function createSession(userId, sessionToken, hoursValid = 24) {
  stmtInsertSession.run(sessionToken, userId, `+${hoursValid} hours`);
}

/**
 * Recupera sessão ativa e válida.
 * @param {string} sessionToken
 * @returns {object|null}
 */
function getSession(sessionToken) {
  return stmtGetSession.get(sessionToken) || null;
}

/**
 * Exclui a sessão (logout).
 * @param {string} sessionToken
 */
function deleteSession(sessionToken) {
  stmtDeleteSession.run(sessionToken);
}

module.exports = {
  createUser,
  getUserByEmail,
  recordFailedAttempt,
  resetFailedAttempts,
  createSession,
  getSession,
  deleteSession
};
