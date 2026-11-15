// ============================================================================
// SUÍTE DE TESTES AUTOMATIZADOS (tests/test-suite.js)
// Executa com o test-runner nativo do Node.js: node --test tests/test-suite.js
// ============================================================================
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const auth = require('../auth.js');
const db = require('../database.js');

describe('🔒 Módulo de Criptografia e Autenticação (auth.js)', () => {
  test('Deve gerar hash seguro diferente da senha em texto puro', async () => {
    const rawPassword = 'MinhaSenhaSecreta123!';
    const hash = await auth.hashPassword(rawPassword);

    assert.ok(hash.includes(':'), 'O hash deve conter o delimitador ":" separando salt e chave');
    assert.notEqual(hash, rawPassword, 'O hash não pode ser igual à senha pura');
  });

  test('Deve gerar hashes diferentes para a mesma senha devido a salts únicos', async () => {
    const rawPassword = 'SenhaIdentica123!';
    const hash1 = await auth.hashPassword(rawPassword);
    const hash2 = await auth.hashPassword(rawPassword);

    assert.notEqual(hash1, hash2, 'Salts aleatórios devem produzir hashes distintos');
  });

  test('Deve validar corretamente a senha original com o hash correspondente', async () => {
    const rawPassword = 'SenhaCorreta#2026';
    const hash = await auth.hashPassword(rawPassword);

    const isValid = await auth.verifyPassword(rawPassword, hash);
    assert.equal(isValid, true, 'Senha correta deve retornar true');
  });

  test('Deve rejeitar senha incorreta', async () => {
    const rawPassword = 'SenhaCorreta#2026';
    const hash = await auth.hashPassword(rawPassword);

    const isValid = await auth.verifyPassword('SenhaInvalida#999', hash);
    assert.equal(isValid, false, 'Senha errada deve retornar false');
  });

  test('Deve lidar com hashes malformados sem estourar exceção', async () => {
    const isValid = await auth.verifyPassword('senha', 'hash_invalido_sem_salt');
    assert.equal(isValid, false, 'Hash malformado deve retornar false com segurança');
  });

  test('Deve sanitizar e normalizar endereços de e-mail', () => {
    assert.equal(auth.sanitizeEmail('  Usuario@Exemplo.COM  '), 'usuario@exemplo.com');
    assert.equal(auth.sanitizeEmail('email_invalido'), null);
    assert.equal(auth.sanitizeEmail(12345), null);
    assert.equal(auth.sanitizeEmail(''), null);
  });

  test('Deve gerar token de sessão de 64 caracteres hexadecimais (32 bytes)', () => {
    const token = auth.generateSessionToken();
    assert.equal(typeof token, 'string');
    assert.equal(token.length, 64);
    assert.match(token, /^[0-9a-f]{64}$/);
  });
});

describe('🗄️ Módulo de Banco de Dados SQLite (database.js)', () => {
  const testEmail = `test_${Date.now()}@dominio.com`;
  let userId;

  test('Deve cadastrar um usuário com sucesso', async () => {
    const hash = await auth.hashPassword('SenhaTeste123!');
    userId = db.createUser(testEmail, hash);

    assert.ok(typeof userId === 'number' && userId > 0, 'O ID do usuário deve ser um número positivo');
  });

  test('Deve impedir o cadastro de e-mail duplicado (Constraint UNIQUE)', async () => {
    const hash = await auth.hashPassword('OutraSenha123!');
    assert.throws(
      () => {
        db.createUser(testEmail, hash);
      },
      /UNIQUE constraint failed/i,
      'Deve lançar erro de unicidade para e-mail repetido'
    );
  });

  test('Deve buscar usuário pelo e-mail com insensibilidade a maiúsculas/minúsculas', () => {
    const user = db.getUserByEmail(testEmail.toUpperCase());
    assert.ok(user !== null, 'Usuário deve ser encontrado mesmo com e-mail em maiúsculas');
    assert.equal(user.email.toLowerCase(), testEmail.toLowerCase());
    assert.equal(user.failed_attempts, 0);
    assert.equal(user.locked_until, null);
  });

  test('Deve registrar tentativas de falha e aplicar bloqueio após 5 erros', () => {
    // 4 falhas: ainda não bloqueado
    for (let i = 1; i <= 4; i++) {
      db.recordFailedAttempt(userId);
      const user = db.getUserByEmail(testEmail);
      assert.equal(user.failed_attempts, i);
      assert.equal(user.locked_until, null, `Na tentativa ${i} a conta não deve estar bloqueada`);
    }

    // 5ª falha: deve ativar locked_until
    db.recordFailedAttempt(userId);
    const userBlocked = db.getUserByEmail(testEmail);
    assert.equal(userBlocked.failed_attempts, 5);
    assert.ok(userBlocked.locked_until !== null, 'A conta deve ser bloqueada na 5ª falha');
  });

  test('Deve resetar tentativas de falha e desbloquear a conta', () => {
    db.resetFailedAttempts(userId);
    const user = db.getUserByEmail(testEmail);
    assert.equal(user.failed_attempts, 0);
    assert.equal(user.locked_until, null);
  });

  test('Deve criar, consultar e invalidar uma sessão de usuário', () => {
    const sessionToken = auth.generateSessionToken();
    db.createSession(userId, sessionToken, 24);

    const activeSession = db.getSession(sessionToken);
    assert.ok(activeSession !== null, 'Sessão criada deve ser recuperável');
    assert.equal(activeSession.user_id, userId);
    assert.equal(activeSession.email.toLowerCase(), testEmail.toLowerCase());

    // Exclusão (Logout)
    db.deleteSession(sessionToken);
    const deletedSession = db.getSession(sessionToken);
    assert.equal(deletedSession, null, 'Sessão excluída não deve mais existir');
  });
});
