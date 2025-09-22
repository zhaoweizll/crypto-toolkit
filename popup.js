/**
 * 加密工具箱 - 用户界面交互逻辑
 * @version 1.0
 */

class PopupController {
  constructor() {
    this.initializeEventListeners();
    this.currentTab = 'aes';
    this.operationInProgress = false;
    this.debounceTimers = new Map();
  }

  // ===== 性能优化方法 =====

  /**
   * 防抖函数 - 防止重复快速操作
   * @param {Function} func - 要执行的函数
   * @param {number} delay - 延迟时间（毫秒）
   * @param {string} key - 唯一标识符
   */
  debounce(func, delay, key) {
    // 清除之前的计时器
    if (this.debounceTimers.has(key)) {
      clearTimeout(this.debounceTimers.get(key));
    }

    // 设置新的计时器
    const timer = setTimeout(() => {
      func();
      this.debounceTimers.delete(key);
    }, delay);
    
    this.debounceTimers.set(key, timer);
  }

  /**
   * 防止重复操作
   * @param {Function} operation - 要执行的异步操作
   * @param {string} operationName - 操作名称
   */
  async preventDuplicateOperation(operation, operationName) {
    if (this.operationInProgress) {
      this.showMessage('操作进行中，请稍候...', 'info');
      return;
    }

    try {
      this.operationInProgress = true;
      this.setOperationState(true, operationName);
      await operation();
    } finally {
      this.operationInProgress = false;
      this.setOperationState(false, operationName);
    }
  }

  /**
   * 设置操作状态（禁用/启用按钮）
   * @param {boolean} isLoading - 是否正在加载
   * @param {string} operationName - 操作名称
   */
  setOperationState(isLoading, operationName) {
    // 使用CSS类而不是内联样式，避免重排
    const container = document.querySelector('.container');
    if (!container) return;

    try {
      if (isLoading) {
        container.classList.add('operation-in-progress');
      } else {
        container.classList.remove('operation-in-progress');
      }
    } catch (error) {
      console.warn('Operation state error:', error);
    }
  }

  // ===== 工具方法 =====
  
  /**
   * 安全获取DOM元素
   * @param {string} id - 元素ID
   * @returns {Element|null} DOM元素或null
   */
  safeGetElement(id) {
    try {
      const element = document.getElementById(id);
      if (!element) {
        console.warn(`Element with id '${id}' not found`);
        return null;
      }
      return element;
    } catch (error) {
      console.error(`Error getting element '${id}':`, error);
      return null;
    }
  }

  // ===== 初始化事件监听器 =====
  initializeEventListeners() {
    // 标签页切换
    document.querySelectorAll('.tab-button').forEach(button => {
      button.addEventListener('click', (e) => {
        this.switchTab(e.target.dataset.tab);
      });
    });

    // AES-GCM 相关事件
    document.getElementById('generate-aes-key').addEventListener('click', () => {
      this.generateAESKey();
    });
    document.getElementById('aes-encrypt').addEventListener('click', () => {
      this.performAESEncryption();
    });
    document.getElementById('aes-decrypt').addEventListener('click', () => {
      this.performAESDecryption();
    });
    document.getElementById('copy-aes-result').addEventListener('click', () => {
      this.copyToClipboard('aes-result');
    });

    // RSA 相关事件
    document.getElementById('generate-rsa-key').addEventListener('click', () => {
      this.generateRSAKeyPair();
    });
    document.getElementById('rsa-encrypt').addEventListener('click', () => {
      this.performRSAEncryption();
    });
    document.getElementById('rsa-decrypt').addEventListener('click', () => {
      this.performRSADecryption();
    });
    document.getElementById('copy-rsa-result').addEventListener('click', () => {
      this.copyToClipboard('rsa-result');
    });

    // RSA 数字签名相关事件
    document.getElementById('rsa-sign').addEventListener('click', () => {
      this.performRSASign();
    });
    document.getElementById('rsa-verify').addEventListener('click', () => {
      this.performRSAVerify();
    });
    document.getElementById('copy-rsa-signature').addEventListener('click', () => {
      this.copyToClipboard('rsa-signature');
    });

    // 哈希算法相关事件
    document.getElementById('calculate-hash').addEventListener('click', () => {
      this.calculateHash();
    });
    document.getElementById('clear-hash').addEventListener('click', () => {
      this.clearHashFields();
    });
    document.getElementById('copy-hash-result').addEventListener('click', () => {
      this.copyToClipboard('hash-result');
    });

    // 实用工具相关事件
    document.getElementById('generate-password').addEventListener('click', () => {
      this.generatePassword();
    });
    document.getElementById('check-password-strength').addEventListener('click', () => {
      this.checkPasswordStrength();
    });
    document.getElementById('copy-password').addEventListener('click', () => {
      this.copyToClipboard('generated-password');
    });
    document.getElementById('clear-all-fields').addEventListener('click', () => {
      this.clearAllFields();
    });
    document.getElementById('clear-keys-only').addEventListener('click', () => {
      this.clearKeysOnly();
    });

    // 密码强度实时检查
    document.getElementById('password-to-check').addEventListener('input', (e) => {
      this.debounce(() => {
        this.checkPasswordStrengthRealtime(e.target.value);
      }, 500, 'passwordStrength');
    });

    // 快捷键支持
    document.addEventListener('keydown', (e) => {
      this.handleKeyboardShortcuts(e);
    });
  }

  // ===== 标签页管理 =====
  switchTab(tabName) {
    // 更新标签按钮状态
    document.querySelectorAll('.tab-button').forEach(button => {
      button.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

    // 更新标签内容显示
    document.querySelectorAll('.tab-content').forEach(content => {
      content.classList.remove('active');
    });
    document.getElementById(tabName).classList.add('active');

    this.currentTab = tabName;
  }

  // ===== 消息显示 =====
  showMessage(message, type = 'info', containerId = null) {
    // 使用固定位置的状态栏显示消息，避免DOM操作导致抖动
    let statusBar = document.getElementById('status-bar');
    if (!statusBar) {
      statusBar = document.createElement('div');
      statusBar.id = 'status-bar';
      statusBar.className = 'status-bar';
      document.body.appendChild(statusBar);
    }

    // 清除之前的样式类
    statusBar.className = 'status-bar';
    
    // 设置消息内容和样式类
    const iconMap = {
      success: '✅',
      error: '❌', 
      info: 'ℹ️'
    };
    
    statusBar.className = `status-bar status-${type} show`;
    statusBar.textContent = `${iconMap[type] || iconMap.info} ${message}`;

    // 2秒后隐藏消息
    clearTimeout(statusBar.hideTimer);
    statusBar.hideTimer = setTimeout(() => {
      statusBar.classList.remove('show');
    }, 2000);
  }

  // ===== 复制功能 =====
  async copyToClipboard(elementId) {
    try {
      const element = document.getElementById(elementId);
      const text = element.value || element.textContent;
      
      if (!text.trim()) {
        this.showMessage('没有内容可复制', 'error');
        return;
      }

      await navigator.clipboard.writeText(text);
      this.showMessage('已复制到剪贴板', 'success');
    } catch (error) {
      console.error('复制失败:', error);
      this.showMessage('复制失败', 'error');
    }
  }

  // ===== AES-GCM 功能 =====
  
  async generateAESKey() {
    await this.preventDuplicateOperation(async () => {
      try {
        this.showMessage('正在生成AES密钥...', 'info');
        const keyHex = await cryptoUtils.generateAESKey();
        document.getElementById('aes-key').value = keyHex;
        this.showMessage('AES密钥生成成功', 'success');
      } catch (error) {
        console.error('生成AES密钥失败:', error);
        this.showMessage('生成AES密钥失败: ' + error.message, 'error');
      }
    }, 'generateAESKey');
  }

  async performAESEncryption() {
    await this.preventDuplicateOperation(async () => {
      const keyInput = this.safeGetElement('aes-key');
      const textInput = this.safeGetElement('aes-text');
      const ivInput = this.safeGetElement('aes-iv');
      const resultOutput = this.safeGetElement('aes-result');

      // 检查元素是否存在
      if (!keyInput || !textInput || !ivInput || !resultOutput) {
        this.showMessage('界面元素加载错误，请刷新页面', 'error');
        return;
      }

      // 验证输入
      if (!keyInput.value.trim()) {
        this.showMessage('请输入或生成AES密钥', 'error');
        try { keyInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      if (!textInput.value.trim()) {
        this.showMessage('请输入要加密的文本', 'error');
        try { textInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      try {
        // 显示加载状态
        this.showMessage('正在加密...', 'info');
        
        const result = await cryptoUtils.encryptAES(
          textInput.value,
          keyInput.value,
          ivInput.value.trim() || null
        );

        if (result.success) {
          // 显示结果（使用组合格式：IV + 密文）
          resultOutput.value = result.combined;
          
          // 如果IV是自动生成的，更新IV输入框
          if (!ivInput.value.trim()) {
            ivInput.value = result.iv;
          }

          this.showMessage('AES加密成功', 'success');
        } else {
          resultOutput.value = '';
          this.showMessage('AES加密失败: ' + result.error, 'error');
        }
      } catch (error) {
        console.error('AES加密出错:', error);
        this.showMessage('AES加密出错: ' + error.message, 'error');
      }
    }, 'aesEncrypt');
  }

  async performAESDecryption() {
    await this.preventDuplicateOperation(async () => {
      const keyInput = document.getElementById('aes-key');
      const textInput = document.getElementById('aes-text');
      const ivInput = document.getElementById('aes-iv');
      const resultOutput = document.getElementById('aes-result');

      // 验证输入
      if (!keyInput.value.trim()) {
        this.showMessage('请输入AES密钥', 'error');
        try { keyInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      if (!textInput.value.trim()) {
        this.showMessage('请输入要解密的密文', 'error');
        try { textInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      try {
        // 显示加载状态
        this.showMessage('正在解密...', 'info');
        
        const result = await cryptoUtils.decryptAES(
          textInput.value,
          keyInput.value,
          ivInput.value.trim() || null
        );

        if (result.success) {
          resultOutput.value = result.plaintext;
          this.showMessage('AES解密成功', 'success');
        } else {
          resultOutput.value = '';
          this.showMessage('AES解密失败: ' + result.error, 'error');
        }
      } catch (error) {
        console.error('AES解密出错:', error);
        this.showMessage('AES解密出错: ' + error.message, 'error');
      }
    }, 'aesDecrypt');
  }

  // ===== RSA 功能 =====

  async generateRSAKeyPair() {
    await this.preventDuplicateOperation(async () => {
      const keySizeSelect = document.getElementById('rsa-key-size');
      const publicKeyTextarea = document.getElementById('rsa-public-key');
      const privateKeyTextarea = document.getElementById('rsa-private-key');

      try {
        const keySize = parseInt(keySizeSelect.value);
        // 显示加载状态，RSA密钥生成时间较长
        this.showMessage(`正在生成RSA ${keySize}位密钥对，请稍候...`, 'info');
        
        const result = await cryptoUtils.generateRSAKeyPair(keySize);

        if (result.success) {
          publicKeyTextarea.value = result.publicKey;
          privateKeyTextarea.value = result.privateKey;
          this.showMessage(`RSA ${keySize}位密钥对生成成功`, 'success');
        } else {
          this.showMessage('RSA密钥对生成失败: ' + result.error, 'error');
        }
      } catch (error) {
        console.error('生成RSA密钥对出错:', error);
        this.showMessage('生成RSA密钥对出错: ' + error.message, 'error');
      }
    }, 'generateRSAKey');
  }

  async performRSAEncryption() {
    await this.preventDuplicateOperation(async () => {
      const publicKeyInput = document.getElementById('rsa-public-key');
      const textInput = document.getElementById('rsa-text');
      const resultOutput = document.getElementById('rsa-result');

      // 验证输入
      if (!publicKeyInput.value.trim()) {
        this.showMessage('请输入或生成RSA公钥', 'error');
        try { publicKeyInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      if (!textInput.value.trim()) {
        this.showMessage('请输入要加密的文本', 'error');
        try { textInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      try {
        // 显示加载状态
        this.showMessage('正在加密...', 'info');
        
        const result = await cryptoUtils.encryptRSA(
          textInput.value,
          publicKeyInput.value
        );

        if (result.success) {
          resultOutput.value = result.ciphertext;
          this.showMessage('RSA加密成功', 'success');
        } else {
          resultOutput.value = '';
          this.showMessage('RSA加密失败: ' + result.error, 'error');
        }
      } catch (error) {
        console.error('RSA加密出错:', error);
        this.showMessage('RSA加密出错: ' + error.message, 'error');
      }
    }, 'rsaEncrypt');
  }

  async performRSADecryption() {
    await this.preventDuplicateOperation(async () => {
      const privateKeyInput = document.getElementById('rsa-private-key');
      const textInput = document.getElementById('rsa-text');
      const resultOutput = document.getElementById('rsa-result');

      // 验证输入
      if (!privateKeyInput.value.trim()) {
        this.showMessage('请输入RSA私钥', 'error');
        try { privateKeyInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      if (!textInput.value.trim()) {
        this.showMessage('请输入要解密的密文', 'error');
        try { textInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      try {
        // 显示加载状态
        this.showMessage('正在解密...', 'info');
        
        const result = await cryptoUtils.decryptRSA(
          textInput.value,
          privateKeyInput.value
        );

        if (result.success) {
          resultOutput.value = result.plaintext;
          this.showMessage('RSA解密成功', 'success');
        } else {
          resultOutput.value = '';
          this.showMessage('RSA解密失败: ' + result.error, 'error');
        }
      } catch (error) {
        console.error('RSA解密出错:', error);
        this.showMessage('RSA解密出错: ' + error.message, 'error');
      }
    }, 'rsaDecrypt');
  }

  // ===== RSA 数字签名功能 =====

  async performRSASign() {
    await this.preventDuplicateOperation(async () => {
      const algorithmSelect = this.safeGetElement('rsa-signature-algorithm');
      const messageInput = this.safeGetElement('rsa-sign-message');
      const privateKeyInput = this.safeGetElement('rsa-sign-private-key');
      const signatureOutput = this.safeGetElement('rsa-signature');

      // 检查元素是否存在
      if (!algorithmSelect || !messageInput || !privateKeyInput || !signatureOutput) {
        this.showMessage('界面元素加载错误，请刷新页面', 'error');
        return;
      }

      // 验证输入
      if (!messageInput.value.trim()) {
        this.showMessage('请输入要签名的消息', 'error');
        try { messageInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      if (!privateKeyInput.value.trim()) {
        this.showMessage('请输入RSA私钥用于签名', 'error');
        try { privateKeyInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      try {
        // 获取选择的算法
        const selectedAlgorithm = algorithmSelect.value;
        const algorithmName = selectedAlgorithm === 'RSA-PSS' ? 'RSA-PSS' : 'SHA256withRSA';
        
        // 显示加载状态
        this.showMessage(`正在生成${algorithmName}数字签名...`, 'info');
        
        const result = await cryptoUtils.signRSA(
          messageInput.value,
          privateKeyInput.value,
          selectedAlgorithm
        );

        if (result.success) {
          signatureOutput.value = result.signature;
          this.showMessage(`${algorithmName}数字签名成功`, 'success');
        } else {
          signatureOutput.value = '';
          this.showMessage(`${algorithmName}数字签名失败: ` + result.error, 'error');
        }
      } catch (error) {
        console.error('RSA数字签名出错:', error);
        this.showMessage('RSA数字签名出错: ' + error.message, 'error');
      }
    }, 'rsaSign');
  }

  async performRSAVerify() {
    await this.preventDuplicateOperation(async () => {
      const algorithmSelect = this.safeGetElement('rsa-signature-algorithm');
      const messageInput = this.safeGetElement('rsa-sign-message');
      const signatureInput = this.safeGetElement('rsa-signature');
      const publicKeyInput = this.safeGetElement('rsa-verify-public-key');
      const verifyResultDiv = this.safeGetElement('rsa-verify-result');

      // 检查元素是否存在
      if (!algorithmSelect || !messageInput || !signatureInput || !publicKeyInput || !verifyResultDiv) {
        this.showMessage('界面元素加载错误，请刷新页面', 'error');
        return;
      }

      // 验证输入
      if (!messageInput.value.trim()) {
        this.showMessage('请输入要验证的消息', 'error');
        try { messageInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      if (!signatureInput.value.trim()) {
        this.showMessage('请输入要验证的签名', 'error');
        try { signatureInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      if (!publicKeyInput.value.trim()) {
        this.showMessage('请输入RSA公钥用于验证', 'error');
        try { publicKeyInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      try {
        // 获取选择的算法
        const selectedAlgorithm = algorithmSelect.value;
        const algorithmName = selectedAlgorithm === 'RSA-PSS' ? 'RSA-PSS' : 'SHA256withRSA';
        
        // 显示加载状态
        this.showMessage(`正在验证${algorithmName}数字签名...`, 'info');
        
        const result = await cryptoUtils.verifyRSA(
          messageInput.value,
          signatureInput.value,
          publicKeyInput.value,
          selectedAlgorithm
        );

        // 清除之前的样式
        verifyResultDiv.className = 'verify-result';

        if (result.success) {
          if (result.valid) {
            verifyResultDiv.className = 'verify-result valid';
            verifyResultDiv.innerHTML = `<span class="verify-icon">✅</span>${algorithmName}签名验证成功 - 签名有效`;
            this.showMessage(`${algorithmName}签名验证通过`, 'success');
          } else {
            verifyResultDiv.className = 'verify-result invalid';
            verifyResultDiv.innerHTML = `<span class="verify-icon">❌</span>${algorithmName}签名验证失败 - 签名无效`;
            this.showMessage(`${algorithmName}签名验证失败`, 'error');
          }
        } else {
          verifyResultDiv.className = 'verify-result error';
          verifyResultDiv.innerHTML = `<span class="verify-icon">⚠️</span>验证出错: ${result.error}`;
          this.showMessage(`${algorithmName}签名验证出错: ` + result.error, 'error');
        }
      } catch (error) {
        console.error('RSA签名验证出错:', error);
        verifyResultDiv.className = 'verify-result error';
        verifyResultDiv.innerHTML = `<span class="verify-icon">⚠️</span>验证出错: ${error.message}`;
        this.showMessage('RSA签名验证出错: ' + error.message, 'error');
      }
    }, 'rsaVerify');
  }

  // ===== 哈希算法功能 =====

  async calculateHash() {
    await this.preventDuplicateOperation(async () => {
      const textInput = document.getElementById('hash-text');
      const algorithmSelect = document.getElementById('hash-algorithm');
      const resultOutput = document.getElementById('hash-result');

      if (!textInput.value.trim()) {
        this.showMessage('请输入要计算哈希的文本', 'error');
        try { textInput.focus(); } catch (e) { console.warn('Focus error:', e); }
        return;
      }

      try {
        this.showMessage('正在计算哈希...', 'info');
        
        const result = await cryptoUtils.calculateHash(
          textInput.value,
          algorithmSelect.value
        );

        if (result.success) {
          resultOutput.value = `算法: ${result.algorithm}\n长度: ${result.length}位\n结果: ${result.hash}`;
          this.showMessage('哈希计算成功', 'success');
        } else {
          resultOutput.value = '';
          this.showMessage('哈希计算失败: ' + result.error, 'error');
        }
      } catch (error) {
        console.error('哈希计算出错:', error);
        this.showMessage('哈希计算出错: ' + error.message, 'error');
      }
    }, 'calculateHash');
  }

  clearHashFields() {
    document.getElementById('hash-text').value = '';
    document.getElementById('hash-result').value = '';
    this.showMessage('哈希字段已清空', 'success');
  }

  // ===== 密码生成和强度检查 =====

  generatePassword() {
    try {
      const lengthInput = document.getElementById('password-length');
      const includeSpecialCheckbox = document.getElementById('include-special');
      const resultInput = document.getElementById('generated-password');

      const length = parseInt(lengthInput.value);
      if (length < 8 || length > 64) {
        this.showMessage('密码长度必须在8-64之间', 'error');
        return;
      }

      const password = cryptoUtils.generateSecurePassword(
        length,
        includeSpecialCheckbox.checked
      );

      resultInput.value = password;
      this.showMessage('安全密码生成成功', 'success');
    } catch (error) {
      console.error('生成密码出错:', error);
      this.showMessage('生成密码出错: ' + error.message, 'error');
    }
  }

  checkPasswordStrength() {
    const passwordInput = document.getElementById('password-to-check');
    if (!passwordInput.value.trim()) {
      this.showMessage('请输入要检查的密码', 'error');
      try { passwordInput.focus(); } catch (e) { console.warn('Focus error:', e); }
      return;
    }
    this.checkPasswordStrengthRealtime(passwordInput.value);
  }

  checkPasswordStrengthRealtime(password) {
    const strengthDiv = document.getElementById('password-strength');
    
    if (!password) {
      strengthDiv.classList.remove('show');
      return;
    }

    const result = cryptoUtils.checkPasswordStrength(password);
    
    strengthDiv.innerHTML = `
      <div class="strength-indicator" style="background-color: ${result.color}; color: white;">
        密码强度: ${result.strength} (${result.score}/5)
      </div>
      ${result.suggestions.length > 0 ? 
        `<div class="suggestions">
          <strong>建议改进:</strong>
          <ul>
            ${result.suggestions.map(s => `<li>${s}</li>`).join('')}
          </ul>
        </div>` : 
        '<div class="suggestions"><strong>✅ 密码强度良好</strong></div>'
      }
    `;
    
    strengthDiv.classList.add('show');
  }

  // ===== 数据清理功能 =====

  clearAllFields() {
    const fieldsToMark = ['aes-key', 'rsa-private-key', 'rsa-public-key', 'aes-text', 'rsa-text', 
                         'aes-result', 'rsa-result', 'hash-text', 'hash-result', 'generated-password', 
                         'password-to-check', 'rsa-sign-message', 'rsa-sign-private-key', 
                         'rsa-verify-public-key', 'rsa-signature'];
    
    fieldsToMark.forEach(fieldId => {
      cryptoUtils.clearSensitiveData(fieldId);
    });
    
    // 清理密码强度显示
    document.getElementById('password-strength').classList.remove('show');
    
    // 清理验证结果显示
    const verifyResultDiv = document.getElementById('rsa-verify-result');
    if (verifyResultDiv) {
      verifyResultDiv.className = 'verify-result';
      verifyResultDiv.innerHTML = '<span class="verify-placeholder">签名验证结果将显示在这里</span>';
    }
    
    this.showMessage('所有敏感数据已安全清理', 'success');
  }

  clearKeysOnly() {
    const keyFields = ['aes-key', 'rsa-private-key', 'rsa-public-key', 'rsa-sign-private-key', 
                      'rsa-verify-public-key', 'generated-password'];
    
    keyFields.forEach(fieldId => {
      cryptoUtils.clearSensitiveData(fieldId);
    });
    
    this.showMessage('密钥数据已安全清理', 'success');
  }

  // ===== 快捷键支持 =====

  handleKeyboardShortcuts(event) {
    // Alt + 数字键切换标签页
    if (event.altKey && !event.ctrlKey && !event.shiftKey) {
      const keyMap = {
        '1': 'aes',
        '2': 'rsa', 
        '3': 'hash',
        '4': 'tools'
      };
      
      if (keyMap[event.key]) {
        event.preventDefault();
        this.switchTab(keyMap[event.key]);
        return;
      }
    }

    // Ctrl + Enter 执行当前标签页的主要操作
    if (event.ctrlKey && event.key === 'Enter') {
      event.preventDefault();
      this.executeMainAction();
      return;
    }

    // Escape 清空当前字段
    if (event.key === 'Escape' && (event.target.tagName.toLowerCase() === 'input' || event.target.tagName.toLowerCase() === 'textarea')) {
      event.target.value = '';
    }
  }

  executeMainAction() {
    switch (this.currentTab) {
      case 'aes':
        this.performAESEncryption();
        break;
      case 'rsa':
        this.performRSAEncryption();
        break;
      case 'hash':
        this.calculateHash();
        break;
      case 'tools':
        this.generatePassword();
        break;
    }
  }
}

// 当DOM加载完成后初始化控制器
document.addEventListener('DOMContentLoaded', () => {
  new PopupController();
});
