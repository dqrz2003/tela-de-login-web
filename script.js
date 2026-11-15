/**
 * ============================================================================
 * SCRIPT FRONTEND: INTEGRAÇÃO COM A API E BANCO DE DADOS
 * ============================================================================
 */
document.addEventListener('DOMContentLoaded', () => {
  // Elementos do DOM
  const loginForm = document.querySelector('.login-form');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const emailError = document.getElementById('email-error');
  const passwordError = document.getElementById('password-error');
  const formAlert = document.getElementById('form-alert');
  const btnSubmit = document.getElementById('btn-submit');
  const btnSubmitText = document.getElementById('btn-submit-text');
  const togglePasswordBtn = document.getElementById('toggle-password');
  
  // Elementos de alternância de modo (Login <-> Cadastro)
  const toggleModeBtn = document.getElementById('toggle-mode-btn');
  const togglePromptText = document.getElementById('toggle-prompt-text');
  const formTitle = document.getElementById('form-title');
  const formSubtitle = document.getElementById('form-subtitle');
  const forgotLink = document.querySelector('.forgot-link');
  const formOptions = document.querySelector('.form-options');
  const socialDivider = document.getElementById('social-divider');
  const socialGroup = document.getElementById('social-group');

  let currentMode = 'login'; // 'login' | 'register'

  // --------------------------------------------------------------------------
  // ALTERNÂNCIA DE MODO (LOGIN vs CADASTRO)
  // --------------------------------------------------------------------------
  function setMode(mode) {
    currentMode = mode;
    hideAlert();
    clearErrors();

    if (mode === 'register') {
      formTitle.textContent = 'Criar nova conta';
      formSubtitle.textContent = 'Cadastre seu e-mail e senha no banco de dados seguro.';
      btnSubmitText.textContent = 'Cadastrar';
      togglePromptText.textContent = 'Já tem uma conta?';
      toggleModeBtn.textContent = 'Entrar';
      
      if (forgotLink) forgotLink.style.display = 'none';
      if (formOptions) formOptions.style.display = 'none';
      if (socialDivider) socialDivider.style.display = 'none';
      if (socialGroup) socialGroup.style.display = 'none';
    } else {
      formTitle.textContent = 'Bem-vindo(a) de volta';
      formSubtitle.textContent = 'Insira suas credenciais para acessar sua conta.';
      btnSubmitText.textContent = 'Entrar';
      togglePromptText.textContent = 'Não tem uma conta?';
      toggleModeBtn.textContent = 'Cadastre-se';

      if (forgotLink) forgotLink.style.display = '';
      if (formOptions) formOptions.style.display = '';
      if (socialDivider) socialDivider.style.display = '';
      if (socialGroup) socialGroup.style.display = '';
    }
  }

  if (toggleModeBtn) {
    toggleModeBtn.addEventListener('click', () => {
      setMode(currentMode === 'login' ? 'register' : 'login');
    });
  }

  // --------------------------------------------------------------------------
  // EXIBIR / OCULTAR SENHA
  // --------------------------------------------------------------------------
  if (togglePasswordBtn && passwordInput) {
    togglePasswordBtn.addEventListener('click', () => {
      const isPassword = passwordInput.getAttribute('type') === 'password';
      const newType = isPassword ? 'text' : 'password';
      
      passwordInput.setAttribute('type', newType);
      togglePasswordBtn.setAttribute('aria-pressed', isPassword ? 'true' : 'false');
      togglePasswordBtn.setAttribute(
        'aria-label', 
        isPassword ? 'Ocultar senha' : 'Mostrar senha'
      );
      passwordInput.focus();
    });
  }

  // --------------------------------------------------------------------------
  // MENSAGENS DE FEEDBACK (ALERTAS)
  // --------------------------------------------------------------------------
  function showAlert(message, type = 'error') {
    formAlert.hidden = false;
    formAlert.className = `form-alert form-alert--${type}`;
    formAlert.textContent = message;
  }

  function hideAlert() {
    formAlert.hidden = true;
    formAlert.textContent = '';
  }

  function clearErrors() {
    emailError.textContent = '';
    passwordError.textContent = '';
  }

  // --------------------------------------------------------------------------
  // ENVIO DO FORMULÁRIO COM FETCH PARA O BACKEND
  // --------------------------------------------------------------------------
  if (loginForm) {
    loginForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      hideAlert();
      clearErrors();

      const email = emailInput.value.trim();
      const password = passwordInput.value;

      // Validação rápida no cliente
      let hasClientError = false;

      if (!emailInput.validity.valid) {
        hasClientError = true;
        if (emailInput.validity.valueMissing) {
          emailError.textContent = 'Por favor, informe seu e-mail.';
        } else if (emailInput.validity.typeMismatch) {
          emailError.textContent = 'Por favor, insira um formato de e-mail válido.';
        }
        emailInput.focus();
      }

      if (!passwordInput.validity.valid) {
        hasClientError = true;
        if (passwordInput.validity.valueMissing) {
          passwordError.textContent = 'Por favor, digite sua senha.';
        } else if (passwordInput.validity.tooShort) {
          passwordError.textContent = 'A senha deve conter no mínimo 6 caracteres.';
        }
        if (!emailError.textContent) {
          passwordInput.focus();
        }
      }

      if (hasClientError) return;

      // Prepara envio
      const endpoint = currentMode === 'register' ? '/api/register' : '/api/login';
      const originalBtnText = btnSubmitText.textContent;
      
      btnSubmit.disabled = true;
      btnSubmitText.textContent = currentMode === 'register' ? 'Cadastrando...' : 'Autenticando...';

      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (!response.ok) {
          showAlert(data.message || 'Ocorreu um erro na requisição.', 'error');
          return;
        }

        // Sucesso
        if (currentMode === 'register') {
          showAlert('Conta criada com sucesso! Agora você já pode fazer login.', 'success');
          // Alterna para o modo de login mantendo o e-mail preenchido
          setMode('login');
          passwordInput.value = '';
          passwordInput.focus();
        } else {
          showAlert(`Bem-vindo(a), ${data.user.email}! Redirecionando para o painel...`, 'success');
          if (data.token) {
            sessionStorage.setItem('auth_token', data.token);
          }
          setTimeout(() => {
            window.location.href = 'dashboard.html';
          }, 800);
        }
      } catch (err) {
        console.error('Erro de conexão:', err);
        showAlert('Não foi possível conectar ao servidor. Certifique-se de iniciar o servidor com "node server.js".', 'error');
      } finally {
        btnSubmit.disabled = false;
        btnSubmitText.textContent = currentMode === 'register' ? 'Cadastrar' : 'Entrar';
      }
    });

    // Limpeza de erros ao digitar
    emailInput.addEventListener('input', () => {
      if (emailInput.validity.valid) emailError.textContent = '';
    });

    passwordInput.addEventListener('input', () => {
      if (passwordInput.validity.valid) passwordError.textContent = '';
    });
  }
});
