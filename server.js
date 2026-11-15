// ============================================================================
// SERVIDOR WEB & API REST SEGURA (server.js) - EXPRESS & CORS
// Configurado para suportar frontend no GitHub Pages e backend no Render
// ============================================================================
const express = require('express');
const cors = require('cors');
const path = require('node:path');
const db = require('./database.js');
const auth = require('./auth.js');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

// Confia no primeiro proxy reverso (essencial no Render para HTTPS e cookies seguros)
app.set('trust proxy', 1);

// ============================================================================
// CONFIGURAÇÃO DE CORS (Cross-Origin Resource Sharing)
// ============================================================================
const allowedOrigins = [
  'https://dqrz2003.github.io',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500'
];

app.use(cors({
  origin: function (origin, callback) {
    // Permite requisições sem origin (mobile apps, curl, etc.) ou se estiver na lista/GitHub Pages
    if (!origin || allowedOrigins.includes(origin) || origin.endsWith('.github.io')) {
      callback(null, true);
    } else {
      callback(new Error('Bloqueado pelas políticas de CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Parser para corpo em formato JSON com limite seguro
app.use(express.json({ limit: '1mb' }));

// Cabeçalhos globais de segurança
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ============================================================================
// ROTAS DA API
// ============================================================================

/**
 * Health check da API
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: isProd ? 'production' : 'development'
  });
});

/**
 * ROTA: CADASTRO DE NOVO USUÁRIO (POST /api/register)
 */
app.post('/api/register', async (req, res) => {
  try {
    const email = auth.sanitizeEmail(req.body.email);
    const password = req.body.password;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Por favor, forneça um endereço de e-mail válido.'
      });
    }

    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'A senha deve conter no mínimo 6 caracteres.'
      });
    }

    // Verifica se o usuário já existe
    const existingUser = db.getUserByEmail(email);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'Este e-mail já está cadastrado no sistema.'
      });
    }

    // Hash criptográfico da senha com scrypt + salt único
    const passwordHash = await auth.hashPassword(password);
    const userId = db.createUser(email, passwordHash);

    return res.status(201).json({
      success: true,
      message: 'Usuário cadastrado com sucesso!',
      userId
    });
  } catch (error) {
    console.error('Erro no cadastro:', error);
    return res.status(500).json({
      success: false,
      message: 'Ocorreu um erro interno no servidor.'
    });
  }
});

/**
 * ROTA: LOGIN DE USUÁRIO (POST /api/login)
 */
app.post('/api/login', async (req, res) => {
  try {
    const email = auth.sanitizeEmail(req.body.email);
    const password = req.body.password;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'E-mail e senha são obrigatórios.'
      });
    }

    const user = db.getUserByEmail(email);

    // Proteção contra enumeração de usuários (timing consistente)
    if (!user) {
      await auth.hashPassword('dummy_password_timing_defense');
      return res.status(401).json({
        success: false,
        message: 'E-mail ou senha incorretos.'
      });
    }

    // Verifica se a conta está temporariamente bloqueada por excesso de tentativas
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const remainingMinutes = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      return res.status(423).json({
        success: false,
        message: `Conta temporariamente bloqueada por segurança devido a excesso de tentativas incorretas. Tente novamente em ${remainingMinutes} minuto(s).`
      });
    }

    // Validação de senha segura com timingSafeEqual
    const isPasswordValid = await auth.verifyPassword(password, user.password_hash);

    if (!isPasswordValid) {
      db.recordFailedAttempt(user.id);
      return res.status(401).json({
        success: false,
        message: 'E-mail ou senha incorretos.'
      });
    }

    // Login bem-sucedido: reseta contador de tentativas falhas
    db.resetFailedAttempts(user.id);

    // Cria token de sessão segura
    const sessionToken = auth.generateSessionToken();
    db.createSession(user.id, sessionToken, 24);

    // Define cookie seguro com sameSite='none' em produção para requisições cross-domain
    res.cookie('auth_token', sessionToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 horas
    });

    return res.status(200).json({
      success: true,
      message: 'Autenticação realizada com sucesso!',
      token: sessionToken,
      user: {
        id: user.id,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Erro no login:', error);
    return res.status(500).json({
      success: false,
      message: 'Ocorreu um erro interno no servidor.'
    });
  }
});

/**
 * Função auxiliar para extrair o token do cabeçalho Bearer ou do cookie
 */
function extractToken(req) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }
  if (req.headers.cookie) {
    const match = req.headers.cookie.match(/auth_token=([^;]+)/);
    if (match) return match[1];
  }
  return null;
}

/**
 * ROTA: VERIFICAÇÃO DE SESSÃO ATIVA (GET /api/me)
 */
app.get('/api/me', (req, res) => {
  const token = extractToken(req);

  if (!token) {
    return res.status(401).json({ success: false, message: 'Não autorizado.' });
  }

  const session = db.getSession(token);
  if (!session) {
    return res.status(401).json({ success: false, message: 'Sessão inválida ou expirada.' });
  }

  return res.status(200).json({
    success: true,
    user: {
      id: session.user_id,
      email: session.email,
      createdAt: session.created_at,
      expiresAt: session.expires_at
    }
  });
});

/**
 * ROTA: LOGOUT (POST /api/logout)
 */
app.post('/api/logout', (req, res) => {
  const token = extractToken(req);

  if (token) {
    db.deleteSession(token);
  }

  // Limpa o cookie de autenticação
  res.clearCookie('auth_token', {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax'
  });

  return res.status(200).json({
    success: true,
    message: 'Sessão encerrada com sucesso.'
  });
});

// ============================================================================
// ARQUIVOS ESTÁTICOS & PÁGINA INICIAL
// ============================================================================
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Inicialização do servidor
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Servidor de autenticação rodando em: http://localhost:${PORT}`);
    console.log(`Ambiente: ${isProd ? 'production' : 'development'}`);
    console.log(`Origem permitida CORS: https://dqrz2003.github.io`);
    console.log(`Banco de dados SQLite ativo: ${path.join(__dirname, 'users.db')}`);
  });
}

module.exports = { app, server: app, requestHandler: app };
