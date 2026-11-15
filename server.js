// ============================================================================
// SERVIDOR WEB & API REST SEGURA (server.js)
// Executável nativamente com: node server.js (sem dependências externas)
// ============================================================================
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const db = require('./database.js');
const auth = require('./auth.js');

const PORT = process.env.PORT || 3000;

// Tipos MIME para arquivos estáticos
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

/**
 * Lê o corpo da requisição JSON de forma segura com limite de tamanho (1MB).
 */
function parseRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    const MAX_SIZE = 1e6; // 1MB

    req.on('data', chunk => {
      body += chunk;
      if (body.length > MAX_SIZE) {
        reject(new Error('Payload Too Large'));
      }
    });

    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', err => reject(err));
  });
}

/**
 * Envia resposta formatada em JSON com cabeçalhos de segurança.
 */
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  });
  res.end(JSON.stringify(data));
}

/**
 * Serve arquivos estáticos (HTML, CSS, JS).
 */
function serveStaticFile(res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Arquivo não encontrado');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Erro interno no servidor');
      }
      return;
    }

    res.writeHead(200, {
      'Content-Type': contentType,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    });
    res.end(content);
  });
}

const requestHandler = async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  try {
    // ------------------------------------------------------------------------
    // ROTA: CADASTRO DE NOVO USUÁRIO (POST /api/register)
    // ------------------------------------------------------------------------
    if (req.method === 'POST' && pathname === '/api/register') {
      const body = await parseRequestBody(req);
      const email = auth.sanitizeEmail(body.email);
      const password = body.password;

      if (!email) {
        return sendJson(res, 400, { 
          success: false, 
          message: 'Por favor, forneça um endereço de e-mail válido.' 
        });
      }

      if (!password || typeof password !== 'string' || password.length < 6) {
        return sendJson(res, 400, { 
          success: false, 
          message: 'A senha deve conter no mínimo 6 caracteres.' 
        });
      }

      // Verifica se o usuário já existe
      const existingUser = db.getUserByEmail(email);
      if (existingUser) {
        return sendJson(res, 409, { 
          success: false, 
          message: 'Este e-mail já está cadastrado no sistema.' 
        });
      }

      // Hash seguro da senha com scrypt + salt único
      const passwordHash = await auth.hashPassword(password);
      const userId = db.createUser(email, passwordHash);

      return sendJson(res, 201, {
        success: true,
        message: 'Usuário cadastrado com sucesso!',
        userId
      });
    }

    // ------------------------------------------------------------------------
    // ROTA: LOGIN DE USUÁRIO (POST /api/login)
    // ------------------------------------------------------------------------
    if (req.method === 'POST' && pathname === '/api/login') {
      const body = await parseRequestBody(req);
      const email = auth.sanitizeEmail(body.email);
      const password = body.password;

      if (!email || !password) {
        return sendJson(res, 400, { 
          success: false, 
          message: 'E-mail e senha são obrigatórios.' 
        });
      }

      const user = db.getUserByEmail(email);

      // Proteção contra enumeração de usuários (timing consistente)
      if (!user) {
        // Gera um hash fictício para mitigar timing attack de usuário inexistente
        await auth.hashPassword('dummy_password_timing_defense');
        return sendJson(res, 401, { 
          success: false, 
          message: 'E-mail ou senha incorretos.' 
        });
      }

      // Verifica se a conta está temporariamente bloqueada por excesso de tentativas
      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        const remainingMinutes = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
        return sendJson(res, 423, {
          success: false,
          message: `Conta temporariamente bloqueada por segurança devido a excesso de tentativas incorretas. Tente novamente em ${remainingMinutes} minuto(s).`
        });
      }

      // Validação de senha segura com timingSafeEqual
      const isPasswordValid = await auth.verifyPassword(password, user.password_hash);

      if (!isPasswordValid) {
        // Incrementa falhas e aplica bloqueio após 5 erros
        db.recordFailedAttempt(user.id);
        return sendJson(res, 401, { 
          success: false, 
          message: 'E-mail ou senha incorretos.' 
        });
      }

      // Login bem-sucedido: reseta contador de tentativas falhas
      db.resetFailedAttempts(user.id);

      // Cria token de sessão segura
      const sessionToken = auth.generateSessionToken();
      db.createSession(user.id, sessionToken, 24);

      return sendJson(res, 200, {
        success: true,
        message: 'Autenticação realizada com sucesso!',
        token: sessionToken,
        user: {
          id: user.id,
          email: user.email
        }
      });
    }

    // ------------------------------------------------------------------------
    // ROTA: VERIFICAÇÃO DE SESSÃO ATIVA (GET /api/me)
    // ------------------------------------------------------------------------
    if (req.method === 'GET' && pathname === '/api/me') {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

      if (!token) {
        return sendJson(res, 401, { success: false, message: 'Não autorizado.' });
      }

      const session = db.getSession(token);
      if (!session) {
        return sendJson(res, 401, { success: false, message: 'Sessão inválida ou expirada.' });
      }

      return sendJson(res, 200, {
        success: true,
        user: {
          id: session.user_id,
          email: session.email,
          createdAt: session.created_at,
          expiresAt: session.expires_at
        }
      });
    }

    // ------------------------------------------------------------------------
    // ROTA: LOGOUT (POST /api/logout)
    // ------------------------------------------------------------------------
    if (req.method === 'POST' && pathname === '/api/logout') {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

      if (token) {
        db.deleteSession(token);
      }

      return sendJson(res, 200, {
        success: true,
        message: 'Sessão encerrada com sucesso.'
      });
    }

    // ------------------------------------------------------------------------
    // ARQUIVOS ESTÁTICOS DO FRONTEND
    // ------------------------------------------------------------------------
    let filePath = path.join(__dirname, pathname === '/' ? 'index.html' : pathname);
    
    // Previne Directory Traversal
    if (!filePath.startsWith(__dirname)) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Acesso negado');
    }

    serveStaticFile(res, filePath);

  } catch (error) {
    console.error('Erro na requisição:', error);
    sendJson(res, 500, { 
      success: false, 
      message: 'Ocorreu um erro interno no servidor.' 
    });
  }
};

const server = http.createServer(requestHandler);

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`Servidor de autenticação rodando em: http://localhost:${PORT}`);
    console.log(`Banco de dados SQLite ativo: ${path.join(__dirname, 'users.db')}`);
  });
}

module.exports = { server, requestHandler };
