// ============================================================================
// MÓDULO DE SEGURANÇA E CRIPTOGRAFIA (auth.js)
// ============================================================================
const crypto = require('node:crypto');

// Configurações do algoritmo scrypt (padrão OWASP / RFC 7914)
const SCRYPT_KEYLEN = 64;
const SCRYPT_OPTIONS = {
  N: 16384, // Custo de CPU/memória
  r: 8,     // Tamanho do bloco
  p: 1      // Paralelismo
};

/**
 * Gera um hash seguro a partir de uma senha usando scrypt com salt criptográfico único.
 * @param {string} password - Senha em texto puro
 * @returns {Promise<string>} - String no formato "salt:hash"
 */
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    // Salt criptograficamente seguro de 16 bytes (128 bits)
    const salt = crypto.randomBytes(16).toString('hex');
    
    crypto.scrypt(password, salt, SCRYPT_KEYLEN, SCRYPT_OPTIONS, (err, derivedKey) => {
      if (err) return reject(err);
      // Retornamos salt e hash concatenados com ':'
      resolve(`${salt}:${derivedKey.toString('hex')}`);
    });
  });
}

/**
 * Valida se uma senha em texto puro corresponde ao hash armazenado no banco.
 * Utiliza crypto.timingSafeEqual para proteger contra Timing Attacks.
 * @param {string} password - Senha fornecida pelo usuário
 * @param {string} storedHash - String "salt:hash" salva no banco
 * @returns {Promise<boolean>}
 */
function verifyPassword(password, storedHash) {
  return new Promise((resolve, reject) => {
    const parts = storedHash.split(':');
    if (parts.length !== 2) {
      return resolve(false);
    }

    const [salt, key] = parts;
    const keyBuffer = Buffer.from(key, 'hex');

    crypto.scrypt(password, salt, SCRYPT_KEYLEN, SCRYPT_OPTIONS, (err, derivedKey) => {
      if (err) return reject(err);

      // timingSafeEqual garante que a comparação leve tempo constante
      if (keyBuffer.length !== derivedKey.length) {
        return resolve(false);
      }

      const match = crypto.timingSafeEqual(keyBuffer, derivedKey);
      resolve(match);
    });
  });
}

/**
 * Gera um token de sessão criptograficamente aleatório de 256 bits (32 bytes).
 * @returns {string} Token em formato hexadecimal
 */
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Higieniza e valida o formato de e-mail.
 * @param {string} email
 * @returns {string|null}
 */
function sanitizeEmail(email) {
  if (typeof email !== 'string') return null;
  const clean = email.trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(clean) ? clean : null;
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateSessionToken,
  sanitizeEmail
};
