// ============================================================================
// TESTES DE INTEGRAÇÃO DA API EXPRESS EM MEMÓRIA (tests/api.test.js)
// ============================================================================
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');
const { EventEmitter } = require('node:events');
const http = require('node:http');
const { app } = require('../server.js');

/**
 * Cria mocks compatíveis com Express e Node.js HTTP para testar a aplicação in-process.
 */
function createMockHttp(method, urlPath, body = null, headers = {}) {
  const payload = body ? JSON.stringify(body) : '';

  const req = new Readable({
    read() {
      if (payload) {
        this.push(payload);
      }
      this.push(null);
    }
  });

  req.method = method;
  req.url = urlPath;
  req.headers = {
    host: 'localhost',
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
    ...headers
  };

  const res = new http.ServerResponse(req);
  res.body = '';

  const responsePromise = new Promise((resolve) => {
    // Intercepta dados enviados
    const originalWrite = res.write;
    const originalEnd = res.end;

    res.write = function (chunk, ...args) {
      if (chunk) res.body += chunk.toString();
      return originalWrite.apply(this, [chunk, ...args]);
    };

    res.end = function (chunk, ...args) {
      if (chunk) res.body += chunk.toString();
      let parsedBody = res.body;
      try {
        parsedBody = JSON.parse(res.body);
      } catch {}
      resolve({ statusCode: res.statusCode, headers: res.getHeaders(), body: parsedBody });
      return originalEnd.apply(this, [chunk, ...args]);
    };
  });

  return { req, res, responsePromise };
}

describe('🌐 Testes de Integração da API Express (server.js)', () => {
  const uniqueEmail = `cliente_${Date.now()}@teste.com`;
  const validPassword = 'SenhaForte2026!';
  let authToken = '';

  test('POST /api/register - Deve criar conta com sucesso (201 Created)', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/register', {
      email: uniqueEmail,
      password: validPassword
    });

    app(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 201);
    assert.equal(response.body.success, true);
    assert.ok(response.body.userId > 0);
  });

  test('POST /api/register - Deve rejeitar e-mail inválido (400 Bad Request)', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/register', {
      email: 'email_invalido',
      password: validPassword
    });

    app(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 400);
    assert.equal(response.body.success, false);
  });

  test('POST /api/register - Deve rejeitar senha com menos de 6 caracteres (400 Bad Request)', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/register', {
      email: `outro_${Date.now()}@teste.com`,
      password: '123'
    });

    app(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 400);
    assert.equal(response.body.success, false);
  });

  test('POST /api/register - Deve rejeitar e-mail já existente (409 Conflict)', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/register', {
      email: uniqueEmail,
      password: 'OutraSenha123'
    });

    app(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 409);
    assert.equal(response.body.success, false);
    assert.match(response.body.message, /já está cadastrado/i);
  });

  test('POST /api/login - Deve autenticar com credenciais corretas (200 OK)', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/login', {
      email: uniqueEmail,
      password: validPassword
    });

    app(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 200);
    assert.equal(response.body.success, true);
    assert.ok(response.body.token, 'Deve retornar o token de sessão');
    authToken = response.body.token;
  });

  test('POST /api/login - Deve rejeitar senha incorreta (401 Unauthorized)', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/login', {
      email: uniqueEmail,
      password: 'SenhaCompletamenteIncorreta'
    });

    app(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 401);
    assert.equal(response.body.success, false);
    assert.match(response.body.message, /incorretos/i);
  });

  test('POST /api/login - Deve rejeitar usuário inexistente com resposta uniforme (401 Unauthorized)', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/login', {
      email: 'inexistente_999@teste.com',
      password: 'QualquerSenha123'
    });

    app(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 401);
    assert.equal(response.body.success, false);
    assert.match(response.body.message, /incorretos/i);
  });

  test('GET /api/me - Deve validar sessão ativa via token Bearer (200 OK)', async () => {
    const { req, res, responsePromise } = createMockHttp('GET', '/api/me', null, {
      authorization: `Bearer ${authToken}`
    });

    app(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 200);
    assert.equal(response.body.success, true);
    assert.equal(response.body.user.email.toLowerCase(), uniqueEmail.toLowerCase());
    assert.ok(response.body.user.createdAt, 'Deve retornar a data de criação do usuário');
  });

  test('GET /api/me - Deve rejeitar requisição sem token (401 Unauthorized)', async () => {
    const { req, res, responsePromise } = createMockHttp('GET', '/api/me');

    app(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 401);
    assert.equal(response.body.success, false);
  });

  test('POST /api/logout - Deve encerrar a sessão e invalidar o token', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/logout', null, {
      authorization: `Bearer ${authToken}`
    });

    app(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 200);
    assert.equal(response.body.success, true);

    // Confirma que a sessão foi revogada no /api/me
    const { req: checkReq, res: checkRes, responsePromise: checkPromise } = createMockHttp('GET', '/api/me', null, {
      authorization: `Bearer ${authToken}`
    });
    app(checkReq, checkRes);
    const checkResponse = await checkPromise;

    assert.equal(checkResponse.statusCode, 401, 'Token revogado não deve mais autenticar');
  });
});
