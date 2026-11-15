/**
 * ============================================================================
 * LÓGICA DO PAINEL DO USUÁRIO & GUARDA DE AUTENTICAÇÃO (dashboard.js)
 * ============================================================================
 */
document.addEventListener('DOMContentLoaded', async () => {
  const loadingEl = document.getElementById('auth-loading');
  const contentEl = document.getElementById('dashboard-content');
  const headerUserEmail = document.getElementById('header-user-email');
  const welcomeUserName = document.getElementById('welcome-user-name');
  const userAvatar = document.getElementById('user-avatar');
  const detailEmail = document.getElementById('detail-email');
  const detailId = document.getElementById('detail-id');
  const detailCreated = document.getElementById('detail-created');
  const accountCreatedAt = document.getElementById('account-created-at');
  const logLoginTime = document.getElementById('log-login-time');
  const btnLogout = document.getElementById('btn-logout');
  const btnRefresh = document.getElementById('btn-refresh-session');

  const token = sessionStorage.getItem('auth_token');

  // Se não houver token no armazenamento de sessão, redireciona para o login
  if (!token) {
    redirectToLogin();
    return;
  }

  /**
   * Redireciona para a página de login
   */
  function redirectToLogin() {
    sessionStorage.removeItem('auth_token');
    window.location.href = 'index.html';
  }

  /**
   * Valida a sessão atual com o backend
   */
  async function verifySession() {
    try {
      const response = await fetch('/api/me', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        redirectToLogin();
        return null;
      }

      const data = await response.json();
      return data.user;
    } catch (err) {
      console.error('Falha ao validar sessão:', err);
      redirectToLogin();
      return null;
    }
  }

  // Executa validação de sessão
  const user = await verifySession();

  if (user) {
    // Preenche as informações no DOM
    const username = user.email.split('@')[0];
    const initial = username.charAt(0).toUpperCase();

    if (headerUserEmail) headerUserEmail.textContent = user.email;
    if (welcomeUserName) welcomeUserName.textContent = username;
    if (userAvatar) userAvatar.textContent = initial;
    if (detailEmail) detailEmail.textContent = user.email;
    if (detailId) detailId.textContent = `#${user.id}`;

    // Formata data de criação se disponível
    if (user.createdAt) {
      const createdDate = new Date(user.createdAt);
      const formattedDate = createdDate.toLocaleDateString('pt-BR', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
      if (detailCreated) detailCreated.textContent = formattedDate;
      if (accountCreatedAt) accountCreatedAt.textContent = `Registrada em ${formattedDate}`;
    }

    if (logLoginTime) {
      const now = new Date();
      logLoginTime.textContent = `Hoje às ${now.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}`;
    }

    // Exibe o painel com transição suave
    if (loadingEl) loadingEl.style.display = 'none';
    if (contentEl) contentEl.hidden = false;
  }

  // Ação de Logout
  if (btnLogout) {
    btnLogout.addEventListener('click', async () => {
      btnLogout.disabled = true;
      btnLogout.innerHTML = '<span>Saindo...</span>';

      try {
        await fetch('/api/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
      } catch (err) {
        console.warn('Erro ao notificar logout no servidor:', err);
      } finally {
        sessionStorage.removeItem('auth_token');
        window.location.href = 'index.html';
      }
    });
  }

  // Ação de verificar sessão em tempo real
  if (btnRefresh) {
    btnRefresh.addEventListener('click', async () => {
      btnRefresh.disabled = true;
      const originalHtml = btnRefresh.innerHTML;
      btnRefresh.innerHTML = '<span>Checando...</span>';

      const validUser = await verifySession();
      if (validUser) {
        btnRefresh.innerHTML = '<span>✔ Sessão Válida!</span>';
        setTimeout(() => {
          btnRefresh.disabled = false;
          btnRefresh.innerHTML = originalHtml;
        }, 1200);
      }
    });
  }
});
