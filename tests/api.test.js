// ============================================================================
// TESTES DE API HTTP EM MEMÓRIA (tests/api.test.js)
// Testa as rotas REST (/api/register, /api/login, /api/me)
// ============================================================================
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');
const { EventEmitter } = require('node:events');
const { requestHandler } = require('../server.js');

/**
 * Cria mocks leves de Request e Response para testar o handler HTTP in-process.
 */
function createMockHttp(method, urlPath, body = null, headers = {}) {
  const req = new Readable({
    read() {
      if (body) {
        this.push(JSON.stringify(body));
      }
      this.push(null);
    }
  });

  req.method = method;
  req.url = urlPath;
  req.headers = { host: 'localhost', ...headers };

  const res = new EventEmitter();
  res.statusCode = 200;
  res.headers = {};
  res.body = '';

  res.writeHead = (statusCode, headers = {}) => {
    res.statusCode = statusCode;
    Object.assign(res.headers, headers);
  };

  const responsePromise = new Promise((resolve) => {
    res.end = (chunk) => {
      if (chunk) res.body += chunk;
      let parsedBody = res.body;
      try {
        parsedBody = JSON.parse(res.body);
      } catch {}
      resolve({ statusCode: res.statusCode, headers: res.headers, body: parsedBody });
    };
  });

  return { req, res, responsePromise };
}

describe('🌐 Testes de Integração da API HTTP (server.js)', () => {
  const uniqueEmail = `cliente_${Date.now()}@teste.com`;
  const validPassword = 'SenhaForte2026!';
  let authToken = '';

  test('POST /api/register - Deve criar conta com sucesso (201 Created)', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/register', {
      email: uniqueEmail,
      password: validPassword
    });

    requestHandler(req, res);
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

    requestHandler(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 400);
    assert.equal(response.body.success, false);
  });

  test('POST /api/register - Deve rejeitar senha com menos de 6 caracteres (400 Bad Request)', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/register', {
      email: `outro_${Date.now()}@teste.com`,
      password: '123'
    });

    requestHandler(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 400);
    assert.equal(response.body.success, false);
  });

  test('POST /api/register - Deve rejeitar e-mail já existente (409 Conflict)', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/register', {
      email: uniqueEmail,
      password: 'OutraSenha123'
    });

    requestHandler(req, res);
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

    requestHandler(req, res);
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

    requestHandler(req, res);
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

    requestHandler(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 401);
    assert.equal(response.body.success, false);
    assert.match(response.body.message, /incorretos/i);
  });

  test('GET /api/me - Deve validar sessão ativa via token Bearer (200 OK)', async () => {
    const { req, res, responsePromise } = createMockHttp('GET', '/api/me', null, {
      authorization: `Bearer ${authToken}`
    });

    requestHandler(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 200);
    assert.equal(response.body.success, true);
    assert.equal(response.body.user.email.toLowerCase(), uniqueEmail.toLowerCase());
    assert.ok(response.body.user.createdAt, 'Deve retornar a data de criação do usuário');
  });

  test('GET /api/me - Deve rejeitar requisição sem token (401 Unauthorized)', async () => {
    const { req, res, responsePromise } = createMockHttp('GET', '/api/me');

    requestHandler(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 401);
    assert.equal(response.body.success, false);
  });

  test('POST /api/logout - Deve encerrar a sessão e invalidar o token', async () => {
    const { req, res, responsePromise } = createMockHttp('POST', '/api/logout', null, {
      authorization: `Bearer ${authToken}`
    });

    requestHandler(req, res);
    const response = await responsePromise;

    assert.equal(response.statusCode, 200);
    assert.equal(response.body.success, true);

    // Confirma que a sessão foi revogada no /api/me
    const { req: checkReq, res: checkRes, responsePromise: checkPromise } = createMockHttp('GET', '/api/me', null, {
      authorization: `Bearer ${authToken}`
    });
    requestHandler(checkReq, checkRes);
    const checkResponse = await checkPromise;

    assert.equal(checkResponse.statusCode, 401, 'Token revogado não deve mais autenticar');
  });
});
