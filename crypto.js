/**
 * 加密工具箱 - 核心加密功能模块
 * 支持AES-GCM、RSA加解密、RSA数字签名、哈希算法等完整功能
 * @version 1.0.1
 */

class CryptoUtils {
  constructor() {
    this.textEncoder = new TextEncoder();
    this.textDecoder = new TextDecoder();
    this.supportedHashAlgorithms = ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
  }

  // ===== 输入验证方法 =====
  
  /**
   * 验证hex字符串格式
   * @param {string} hex - 要验证的hex字符串
   * @param {number} expectedLength - 期望的字符串长度（可选）
   * @returns {boolean} 是否有效
   */
  isValidHex(hex, expectedLength = null) {
    if (!hex || typeof hex !== 'string') return false;
    const hexPattern = /^[0-9a-fA-F]+$/;
    if (!hexPattern.test(hex)) return false;
    if (expectedLength !== null && hex.length !== expectedLength) return false;
    return hex.length % 2 === 0;
  }

  /**
   * 验证PEM格式
   * @param {string} pem - 要验证的PEM字符串
   * @param {string} type - 期望的类型（PUBLIC KEY 或 PRIVATE KEY）
   * @returns {boolean} 是否有效
   */
  isValidPEM(pem, type = null) {
    if (!pem || typeof pem !== 'string') return false;
    const pemPattern = /^-----BEGIN\s+([A-Z\s]+)-----\s*\n(.*)\n-----END\s+([A-Z\s]+)-----\s*$/ms;
    const match = pem.match(pemPattern);
    if (!match) return false;
    if (type && match[1] !== type) return false;
    return match[1] === match[3];
  }

  /**
   * 验证Base64格式
   * @param {string} base64 - 要验证的Base64字符串
   * @param {number} expectedBytes - 期望的字节数（可选）
   * @returns {boolean} 是否有效
   */
  isValidBase64(base64, expectedBytes = null) {
    if (!base64 || typeof base64 !== 'string') return false;
    try {
      const decoded = atob(base64);
      if (expectedBytes !== null && decoded.length !== expectedBytes) return false;
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * 验证AES密钥格式和长度
   * @param {string} keyBase64 - Base64格式的AES密钥
   * @returns {Object} 验证结果，包含是否有效和密钥长度
   */
  validateAESKey(keyBase64) {
    if (!keyBase64 || typeof keyBase64 !== 'string') {
      return { valid: false, error: '请提供有效的密钥' };
    }

    try {
      const decoded = atob(keyBase64);
      const keyLength = decoded.length;
      
      if (keyLength === 16) {
        return { valid: true, keyLength: 128 }; // 128位密钥
      } else if (keyLength === 32) {
        return { valid: true, keyLength: 256 }; // 256位密钥
      } else {
        return { 
          valid: false, 
          error: `AES密钥长度不正确，应为16字节(128位)或32字节(256位)，当前为${keyLength}字节` 
        };
      }
    } catch (error) {
      return { valid: false, error: 'AES密钥必须是有效的Base64格式字符串' };
    }
  }

  // ===== 工具方法 =====
  
  /**
   * 将ArrayBuffer转换为hex字符串
   */
  arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * 将hex字符串转换为ArrayBuffer
   * @param {string} hex - hex字符串
   * @returns {ArrayBuffer} 转换后的ArrayBuffer
   * @throws {Error} 如果hex字符串无效
   */
  hexToArrayBuffer(hex) {
    if (!this.isValidHex(hex)) {
      throw new Error('无效的hex字符串格式');
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes.buffer;
  }

  /**
   * 将ArrayBuffer转换为Base64
   */
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * 将Base64转换为ArrayBuffer
   */
  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // ===== 哈希算法功能 =====

  /**
   * 计算文本的哈希值
   * @param {string} text - 要计算哈希的文本
   * @param {string} algorithm - 哈希算法 (MD5, SHA-1, SHA-256, SHA-384, SHA-512)
   * @returns {Promise<Object>} 包含哈希结果的对象
   */
  async calculateHash(text, algorithm = 'SHA-256') {
    try {
      if (!text || typeof text !== 'string') {
        throw new Error('请提供有效的文本内容');
      }
      
      if (!this.supportedHashAlgorithms.includes(algorithm)) {
        throw new Error(`不支持的哈希算法: ${algorithm}`);
      }

      // WebCrypto不支持MD5，这里使用内置实现；其它算法仍走原生API
      let hashHex;
      if (algorithm === 'MD5') {
        hashHex = this.calculateMD5(text);
      } else {
        const data = this.textEncoder.encode(text);
        const hashBuffer = await crypto.subtle.digest(algorithm, data);
        hashHex = this.arrayBufferToHex(hashBuffer);
      }
      
      return {
        success: true,
        algorithm: algorithm,
        hash: hashHex,
        length: hashHex.length * 4 // 位长度
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * 计算MD5
   * @param {string} text - 要计算哈希的文本
   * @returns {string} hex格式的MD5
   */
  calculateMD5(text) {
    // 将文本转换为二进制字符串（基于UTF-8字节）
    const binary = Array.from(this.textEncoder.encode(text))
      .map(b => String.fromCharCode(b))
      .join('');

    // 以下实现改写自常见的MD5参考实现，保持紧凑以适配扩展页面
    const rotateLeft = (x, c) => (x << c) | (x >>> (32 - c));
    const addUnsigned = (a, b) => {
      const lsw = (a & 0xffff) + (b & 0xffff);
      const msw = (a >>> 16) + (b >>> 16) + (lsw >>> 16);
      return (msw << 16) | (lsw & 0xffff);
    };
    const F = (x, y, z) => (x & y) | (~x & z);
    const G = (x, y, z) => (x & z) | (y & ~z);
    const H = (x, y, z) => x ^ y ^ z;
    const I = (x, y, z) => y ^ (x | ~z);

    const FF = (a, b, c, d, x, s, ac) => addUnsigned(rotateLeft(addUnsigned(addUnsigned(a, F(b, c, d)), addUnsigned(x, ac)), s), b);
    const GG = (a, b, c, d, x, s, ac) => addUnsigned(rotateLeft(addUnsigned(addUnsigned(a, G(b, c, d)), addUnsigned(x, ac)), s), b);
    const HH = (a, b, c, d, x, s, ac) => addUnsigned(rotateLeft(addUnsigned(addUnsigned(a, H(b, c, d)), addUnsigned(x, ac)), s), b);
    const II = (a, b, c, d, x, s, ac) => addUnsigned(rotateLeft(addUnsigned(addUnsigned(a, I(b, c, d)), addUnsigned(x, ac)), s), b);

    const convertToWordArray = (str) => {
      const messageLength = str.length;
      const numberOfWordsTemp = ((messageLength + 8) >>> 6 << 4) + 16;
      const wordArray = new Array(numberOfWordsTemp - 1);
      for (let i = 0; i < numberOfWordsTemp; i++) wordArray[i] = 0;

      let bytePosition = 0;
      let byteCount = 0;
      while (byteCount < messageLength) {
        const wordCount = (byteCount >>> 2);
        bytePosition = (byteCount % 4) * 8;
        wordArray[wordCount] |= str.charCodeAt(byteCount) << bytePosition;
        byteCount++;
      }

      wordArray[(byteCount >>> 2)] |= 0x80 << ((byteCount % 4) * 8);
      wordArray[numberOfWordsTemp - 2] = messageLength << 3;
      wordArray[numberOfWordsTemp - 1] = messageLength >>> 29;
      return wordArray;
    };

    const wordToHex = (value) => {
      let hexValue = '';
      for (let i = 0; i <= 3; i++) {
        const byte = (value >>> (i * 8)) & 255;
        const temp = '0' + byte.toString(16);
        hexValue += temp.substr(temp.length - 2, 2);
      }
      return hexValue;
    };

    const x = convertToWordArray(binary);
    let a = 0x67452301;
    let b = 0xefcdab89;
    let c = 0x98badcfe;
    let d = 0x10325476;

    for (let k = 0; k < x.length; k += 16) {
      const aa = a, bb = b, cc = c, dd = d;

      // 第一轮
      a = FF(a, b, c, d, x[k + 0], 7, 0xd76aa478);
      d = FF(d, a, b, c, x[k + 1], 12, 0xe8c7b756);
      c = FF(c, d, a, b, x[k + 2], 17, 0x242070db);
      b = FF(b, c, d, a, x[k + 3], 22, 0xc1bdceee);
      a = FF(a, b, c, d, x[k + 4], 7, 0xf57c0faf);
      d = FF(d, a, b, c, x[k + 5], 12, 0x4787c62a);
      c = FF(c, d, a, b, x[k + 6], 17, 0xa8304613);
      b = FF(b, c, d, a, x[k + 7], 22, 0xfd469501);
      a = FF(a, b, c, d, x[k + 8], 7, 0x698098d8);
      d = FF(d, a, b, c, x[k + 9], 12, 0x8b44f7af);
      c = FF(c, d, a, b, x[k + 10], 17, 0xffff5bb1);
      b = FF(b, c, d, a, x[k + 11], 22, 0x895cd7be);
      a = FF(a, b, c, d, x[k + 12], 7, 0x6b901122);
      d = FF(d, a, b, c, x[k + 13], 12, 0xfd987193);
      c = FF(c, d, a, b, x[k + 14], 17, 0xa679438e);
      b = FF(b, c, d, a, x[k + 15], 22, 0x49b40821);

      // 第二轮
      a = GG(a, b, c, d, x[k + 1], 5, 0xf61e2562);
      d = GG(d, a, b, c, x[k + 6], 9, 0xc040b340);
      c = GG(c, d, a, b, x[k + 11], 14, 0x265e5a51);
      b = GG(b, c, d, a, x[k + 0], 20, 0xe9b6c7aa);
      a = GG(a, b, c, d, x[k + 5], 5, 0xd62f105d);
      d = GG(d, a, b, c, x[k + 10], 9, 0x02441453);
      c = GG(c, d, a, b, x[k + 15], 14, 0xd8a1e681);
      b = GG(b, c, d, a, x[k + 4], 20, 0xe7d3fbc8);
      a = GG(a, b, c, d, x[k + 9], 5, 0x21e1cde6);
      d = GG(d, a, b, c, x[k + 14], 9, 0xc33707d6);
      c = GG(c, d, a, b, x[k + 3], 14, 0xf4d50d87);
      b = GG(b, c, d, a, x[k + 8], 20, 0x455a14ed);
      a = GG(a, b, c, d, x[k + 13], 5, 0xa9e3e905);
      d = GG(d, a, b, c, x[k + 2], 9, 0xfcefa3f8);
      c = GG(c, d, a, b, x[k + 7], 14, 0x676f02d9);
      b = GG(b, c, d, a, x[k + 12], 20, 0x8d2a4c8a);

      // 第三轮
      a = HH(a, b, c, d, x[k + 5], 4, 0xfffa3942);
      d = HH(d, a, b, c, x[k + 8], 11, 0x8771f681);
      c = HH(c, d, a, b, x[k + 11], 16, 0x6d9d6122);
      b = HH(b, c, d, a, x[k + 14], 23, 0xfde5380c);
      a = HH(a, b, c, d, x[k + 1], 4, 0xa4beea44);
      d = HH(d, a, b, c, x[k + 4], 11, 0x4bdecfa9);
      c = HH(c, d, a, b, x[k + 7], 16, 0xf6bb4b60);
      b = HH(b, c, d, a, x[k + 10], 23, 0xbebfbc70);
      a = HH(a, b, c, d, x[k + 13], 4, 0x289b7ec6);
      d = HH(d, a, b, c, x[k + 0], 11, 0xeaa127fa);
      c = HH(c, d, a, b, x[k + 3], 16, 0xd4ef3085);
      b = HH(b, c, d, a, x[k + 6], 23, 0x04881d05);
      a = HH(a, b, c, d, x[k + 9], 4, 0xd9d4d039);
      d = HH(d, a, b, c, x[k + 12], 11, 0xe6db99e5);
      c = HH(c, d, a, b, x[k + 15], 16, 0x1fa27cf8);
      b = HH(b, c, d, a, x[k + 2], 23, 0xc4ac5665);

      // 第四轮
      a = II(a, b, c, d, x[k + 0], 6, 0xf4292244);
      d = II(d, a, b, c, x[k + 7], 10, 0x432aff97);
      c = II(c, d, a, b, x[k + 14], 15, 0xab9423a7);
      b = II(b, c, d, a, x[k + 5], 21, 0xfc93a039);
      a = II(a, b, c, d, x[k + 12], 6, 0x655b59c3);
      d = II(d, a, b, c, x[k + 3], 10, 0x8f0ccc92);
      c = II(c, d, a, b, x[k + 10], 15, 0xffeff47d);
      b = II(b, c, d, a, x[k + 1], 21, 0x85845dd1);
      a = II(a, b, c, d, x[k + 8], 6, 0x6fa87e4f);
      d = II(d, a, b, c, x[k + 15], 10, 0xfe2ce6e0);
      c = II(c, d, a, b, x[k + 6], 15, 0xa3014314);
      b = II(b, c, d, a, x[k + 13], 21, 0x4e0811a1);
      a = II(a, b, c, d, x[k + 4], 6, 0xf7537e82);
      d = II(d, a, b, c, x[k + 11], 10, 0xbd3af235);
      c = II(c, d, a, b, x[k + 2], 15, 0x2ad7d2bb);
      b = II(b, c, d, a, x[k + 9], 21, 0xeb86d391);

      a = addUnsigned(a, aa);
      b = addUnsigned(b, bb);
      c = addUnsigned(c, cc);
      d = addUnsigned(d, dd);
    }

    return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
  }

  // ===== AES-GCM 功能 =====

  /**
   * 生成AES密钥
   * @param {number} keyLength - 密钥长度（128或256位）
   * @returns {Promise<string>} Base64格式的密钥
   */
  async generateAESKey(keyLength = 256) {
    if (keyLength !== 128 && keyLength !== 256) {
      throw new Error('密钥长度只支持128位或256位');
    }

    const key = await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: keyLength
      },
      true,
      ['encrypt', 'decrypt']
    );
    
    const exportedKey = await crypto.subtle.exportKey('raw', key);
    return this.arrayBufferToBase64(exportedKey);
  }

  /**
   * 生成随机IV
   * @returns {string} Base64格式的IV
   */
  generateIV() {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return this.arrayBufferToBase64(iv);
  }

  /**
   * AES-GCM加密
   * @param {string} plaintext - 要加密的明文
   * @param {string} keyBase64 - Base64格式的密钥
   * @param {string|null} ivBase64 - Base64格式的IV（可选）
   * @returns {Promise<Object>} 加密结果
   */
  async encryptAES(plaintext, keyBase64, ivBase64 = null) {
    try {
      // 输入验证
      if (!plaintext || typeof plaintext !== 'string') {
        throw new Error('请提供有效的明文内容');
      }
      
      if (!keyBase64 || typeof keyBase64 !== 'string') {
        throw new Error('请提供有效的密钥');
      }

      // 如果没有提供IV，生成一个新的
      if (!ivBase64) {
        ivBase64 = this.generateIV();
      }

      // 验证密钥格式和长度
      const keyValidation = this.validateAESKey(keyBase64);
      if (!keyValidation.valid) {
        throw new Error(keyValidation.error);
      }

      // 验证IV格式和长度（Base64，12字节）
      if (!this.isValidBase64(ivBase64, 12)) {
        throw new Error('IV必须是有效的Base64格式字符串(12字节)');
      }

      // 将Base64密钥转换为ArrayBuffer并导入
      const keyBuffer = this.base64ToArrayBuffer(keyBase64);
      const key = await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        {
          name: 'AES-GCM',
          length: keyValidation.keyLength
        },
        false,
        ['encrypt']
      );

      // 准备IV
      const iv = this.base64ToArrayBuffer(ivBase64);
      
      // 加密
      const encryptedBuffer = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        key,
        this.textEncoder.encode(plaintext)
      );

      // 返回结果，包含IV和密文
      const encryptedBase64 = this.arrayBufferToBase64(encryptedBuffer);
      return {
        success: true,
        ciphertext: encryptedBase64,
        iv: ivBase64,
        combined: ivBase64 + '.' + encryptedBase64 // 使用点号分隔IV和密文
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * AES-GCM解密
   * @param {string} ciphertext - 要解密的密文（或组合格式）
   * @param {string} keyBase64 - Base64格式的密钥
   * @param {string|null} ivBase64 - Base64格式的IV（可选）
   * @returns {Promise<Object>} 解密结果
   */
  async decryptAES(ciphertext, keyBase64, ivBase64 = null) {
    try {
      // 输入验证
      if (!ciphertext || typeof ciphertext !== 'string') {
        throw new Error('请提供有效的密文内容');
      }
      
      if (!keyBase64 || typeof keyBase64 !== 'string') {
        throw new Error('请提供有效的密钥');
      }

      let actualCiphertext = ciphertext;
      let actualIv = ivBase64;

      // 如果没有单独提供IV，尝试从组合格式中提取
      if (!actualIv) {
        // 检查是否为新格式（使用点号分隔）
        if (ciphertext.includes('.')) {
          const parts = ciphertext.split('.');
          if (parts.length !== 2) {
            throw new Error('组合格式密文无效，应为 IV.密文 格式');
          }
          actualIv = parts[0];
          actualCiphertext = parts[1];
        } else {
          // 兼容旧的hex格式
          if (ciphertext.length < 24) {
            throw new Error('密文格式无效，长度不足');
          }
          // 假设前24个字符是hex格式的IV
          const hexIv = ciphertext.substring(0, 24);
          actualCiphertext = ciphertext.substring(24);
          
          // 将hex IV转换为Base64
          try {
            const ivBuffer = this.hexToArrayBuffer(hexIv);
            actualIv = this.arrayBufferToBase64(ivBuffer);
            // 将hex密文转换为Base64
            const ciphertextBuffer = this.hexToArrayBuffer(actualCiphertext);
            actualCiphertext = this.arrayBufferToBase64(ciphertextBuffer);
          } catch (error) {
            throw new Error('无法解析旧格式密文');
          }
        }
      }

      // 验证密钥格式和长度
      const keyValidation = this.validateAESKey(keyBase64);
      if (!keyValidation.valid) {
        throw new Error(keyValidation.error);
      }

      // 验证IV格式和长度（Base64，12字节）
      if (!this.isValidBase64(actualIv, 12)) {
        throw new Error('IV必须是有效的Base64格式字符串(12字节)');
      }

      // 验证密文格式（Base64）
      if (!this.isValidBase64(actualCiphertext)) {
        throw new Error('密文必须是有效的Base64格式字符串');
      }

      // 将Base64密钥转换为ArrayBuffer并导入
      const keyBuffer = this.base64ToArrayBuffer(keyBase64);
      const key = await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        {
          name: 'AES-GCM',
          length: keyValidation.keyLength
        },
        false,
        ['decrypt']
      );

      // 准备IV和密文
      const iv = this.base64ToArrayBuffer(actualIv);
      const encryptedBuffer = this.base64ToArrayBuffer(actualCiphertext);
      
      // 解密
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        key,
        encryptedBuffer
      );

      const plaintext = this.textDecoder.decode(decryptedBuffer);
      
      return {
        success: true,
        plaintext: plaintext
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  // ===== RSA 功能 =====

  /**
   * 生成RSA密钥对
   * @param {number} keySize - 密钥大小（默认2048）
   * @param {string} purpose - 用途：'encryption'（加密）、'signature'（签名）或'both'（两者）
   * @returns {Promise<Object>} 密钥对生成结果
   */
  async generateRSAKeyPair(keySize = 2048, purpose = 'both') {
    try {
      let encryptKeyPair = null;
      let signKeyPair = null;

      // 根据用途生成不同的密钥对
      if (purpose === 'encryption' || purpose === 'both') {
        // 生成用于加密的RSA密钥对
        encryptKeyPair = await crypto.subtle.generateKey(
          {
            name: 'RSA-OAEP',
            modulusLength: keySize,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
          },
          true,
          ['encrypt', 'decrypt']
        );
      }

      if (purpose === 'signature' || purpose === 'both') {
        // 生成用于签名的RSA密钥对
        signKeyPair = await crypto.subtle.generateKey(
          {
            name: 'RSA-PSS',
            modulusLength: keySize,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
          },
          true,
          ['sign', 'verify']
        );
      }

      const result = { success: true };

      // 如果需要加密密钥对
      if (encryptKeyPair) {
        const publicKeyBuffer = await crypto.subtle.exportKey('spki', encryptKeyPair.publicKey);
        const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', encryptKeyPair.privateKey);
        
        result.encryptionKeys = {
          publicKey: this.formatPEM(this.arrayBufferToBase64(publicKeyBuffer), 'PUBLIC KEY'),
          privateKey: this.formatPEM(this.arrayBufferToBase64(privateKeyBuffer), 'PRIVATE KEY')
        };
      }

      // 如果需要签名密钥对
      if (signKeyPair) {
        const publicKeyBuffer = await crypto.subtle.exportKey('spki', signKeyPair.publicKey);
        const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', signKeyPair.privateKey);
        
        result.signatureKeys = {
          publicKey: this.formatPEM(this.arrayBufferToBase64(publicKeyBuffer), 'PUBLIC KEY'),
          privateKey: this.formatPEM(this.arrayBufferToBase64(privateKeyBuffer), 'PRIVATE KEY')
        };
      }

      // 向后兼容：如果是both，也提供旧格式的输出（使用签名密钥）
      if (purpose === 'both') {
        result.publicKey = result.signatureKeys.publicKey;
        result.privateKey = result.signatureKeys.privateKey;
      } else if (purpose === 'encryption') {
        result.publicKey = result.encryptionKeys.publicKey;
        result.privateKey = result.encryptionKeys.privateKey;
      } else if (purpose === 'signature') {
        result.publicKey = result.signatureKeys.publicKey;
        result.privateKey = result.signatureKeys.privateKey;
      }

      return result;

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * 格式化PEM
   */
  formatPEM(base64, type) {
    const pemString = base64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${type}-----\n${pemString}\n-----END ${type}-----`;
  }

  /**
   * 解析PEM格式
   */
  parsePEM(pem) {
    return pem
      .replace(/-----BEGIN [^-]+-----/, '')
      .replace(/-----END [^-]+-----/, '')
      .replace(/\s/g, '');
  }

  /**
   * RSA加密
   * @param {string} plaintext - 要加密的明文
   * @param {string} publicKeyPem - PEM格式的公钥
   * @returns {Promise<Object>} 加密结果
   */
  async encryptRSA(plaintext, publicKeyPem) {
    try {
      // 输入验证
      if (!plaintext || typeof plaintext !== 'string') {
        throw new Error('请提供有效的明文内容');
      }
      
      if (!publicKeyPem || typeof publicKeyPem !== 'string') {
        throw new Error('请提供有效的公钥');
      }

      // 验证PEM格式
      if (!this.isValidPEM(publicKeyPem, 'PUBLIC KEY')) {
        throw new Error('公钥格式无效，请提供标准的PEM格式公钥');
      }

      // 检查明文长度（RSA加密有长度限制）
      const maxPlaintextLength = 245; // 2048位密钥的大致限制
      if (plaintext.length > maxPlaintextLength) {
        throw new Error(`明文过长，RSA最多支持约${maxPlaintextLength}字符`);
      }

      // 解析PEM格式的公钥
      const publicKeyBase64 = this.parsePEM(publicKeyPem);
      const publicKeyBuffer = this.base64ToArrayBuffer(publicKeyBase64);

      // 导入公钥
      const publicKey = await crypto.subtle.importKey(
        'spki',
        publicKeyBuffer,
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256'
        },
        false,
        ['encrypt']
      );

      // 加密
      const encryptedBuffer = await crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP'
        },
        publicKey,
        this.textEncoder.encode(plaintext)
      );

      const encryptedBase64 = this.arrayBufferToBase64(encryptedBuffer);
      
      return {
        success: true,
        ciphertext: encryptedBase64
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * RSA解密
   * @param {string} ciphertext - Base64格式的密文
   * @param {string} privateKeyPem - PEM格式的私钥
   * @returns {Promise<Object>} 解密结果
   */
  async decryptRSA(ciphertext, privateKeyPem) {
    try {
      // 输入验证
      if (!ciphertext || typeof ciphertext !== 'string') {
        throw new Error('请提供有效的密文内容');
      }
      
      if (!privateKeyPem || typeof privateKeyPem !== 'string') {
        throw new Error('请提供有效的私钥');
      }

      // 验证PEM格式
      if (!this.isValidPEM(privateKeyPem, 'PRIVATE KEY')) {
        throw new Error('私钥格式无效，请提供标准的PEM格式私钥');
      }

      // 验证Base64格式
      try {
        atob(ciphertext);
      } catch (error) {
        throw new Error('密文必须是有效的Base64格式');
      }

      // 解析PEM格式的私钥
      const privateKeyBase64 = this.parsePEM(privateKeyPem);
      const privateKeyBuffer = this.base64ToArrayBuffer(privateKeyBase64);

      // 导入私钥
      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        privateKeyBuffer,
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256'
        },
        false,
        ['decrypt']
      );

      // 将base64密文转换为ArrayBuffer
      const encryptedBuffer = this.base64ToArrayBuffer(ciphertext);

      // 解密
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: 'RSA-OAEP'
        },
        privateKey,
        encryptedBuffer
      );

      const plaintext = this.textDecoder.decode(decryptedBuffer);
      
      return {
        success: true,
        plaintext: plaintext
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * RSA数字签名
   * @param {string} message - 要签名的消息
   * @param {string} privateKeyPem - PEM格式的私钥
   * @param {string} algorithm - 签名算法 ('RSA-PSS' 或 'RSASSA-PKCS1-v1_5')
   * @returns {Promise<Object>} 签名结果
   */
  async signRSA(message, privateKeyPem, algorithm = 'RSA-PSS') {
    try {
      // 输入验证
      if (!message || typeof message !== 'string') {
        throw new Error('请提供有效的消息内容');
      }
      
      if (!privateKeyPem || typeof privateKeyPem !== 'string') {
        throw new Error('请提供有效的私钥');
      }

      // 验证PEM格式
      if (!this.isValidPEM(privateKeyPem, 'PRIVATE KEY')) {
        throw new Error('私钥格式无效，请提供标准的PEM格式私钥');
      }

      // 输入验证算法参数
      if (algorithm !== 'RSA-PSS' && algorithm !== 'RSASSA-PKCS1-v1_5') {
        throw new Error('不支持的签名算法，请选择 RSA-PSS 或 RSASSA-PKCS1-v1_5');
      }

      // 解析PEM格式的私钥
      const privateKeyBase64 = this.parsePEM(privateKeyPem);
      const privateKeyBuffer = this.base64ToArrayBuffer(privateKeyBase64);

      // 导入私钥
      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        privateKeyBuffer,
        {
          name: algorithm,
          hash: 'SHA-256'
        },
        false,
        ['sign']
      );

      // 根据算法配置签名参数
      let signParams;
      if (algorithm === 'RSA-PSS') {
        signParams = {
          name: 'RSA-PSS',
          saltLength: 32, // 盐长度等于哈希长度
        };
      } else {
        signParams = {
          name: 'RSASSA-PKCS1-v1_5'
        };
      }

      // 签名
      const signatureBuffer = await crypto.subtle.sign(
        signParams,
        privateKey,
        this.textEncoder.encode(message)
      );

      const signatureBase64 = this.arrayBufferToBase64(signatureBuffer);
      
      return {
        success: true,
        signature: signatureBase64,
        message: message,
        algorithm: algorithm,
        hashAlgorithm: 'SHA-256'
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * RSA验证签名
   * @param {string} message - 原始消息
   * @param {string} signature - Base64格式的签名
   * @param {string} publicKeyPem - PEM格式的公钥
   * @param {string} algorithm - 签名算法 ('RSA-PSS' 或 'RSASSA-PKCS1-v1_5')
   * @returns {Promise<Object>} 验证结果
   */
  async verifyRSA(message, signature, publicKeyPem, algorithm = 'RSA-PSS') {
    try {
      // 输入验证
      if (!message || typeof message !== 'string') {
        throw new Error('请提供有效的消息内容');
      }
      
      if (!signature || typeof signature !== 'string') {
        throw new Error('请提供有效的签名');
      }
      
      if (!publicKeyPem || typeof publicKeyPem !== 'string') {
        throw new Error('请提供有效的公钥');
      }

      // 验证PEM格式
      if (!this.isValidPEM(publicKeyPem, 'PUBLIC KEY')) {
        throw new Error('公钥格式无效，请提供标准的PEM格式公钥');
      }

      // 输入验证算法参数
      if (algorithm !== 'RSA-PSS' && algorithm !== 'RSASSA-PKCS1-v1_5') {
        throw new Error('不支持的签名算法，请选择 RSA-PSS 或 RSASSA-PKCS1-v1_5');
      }

      // 验证Base64格式
      try {
        atob(signature);
      } catch (error) {
        throw new Error('签名必须是有效的Base64格式');
      }

      // 解析PEM格式的公钥
      const publicKeyBase64 = this.parsePEM(publicKeyPem);
      const publicKeyBuffer = this.base64ToArrayBuffer(publicKeyBase64);

      // 导入公钥
      const publicKey = await crypto.subtle.importKey(
        'spki',
        publicKeyBuffer,
        {
          name: algorithm,
          hash: 'SHA-256'
        },
        false,
        ['verify']
      );

      // 将base64签名转换为ArrayBuffer
      const signatureBuffer = this.base64ToArrayBuffer(signature);

      // 根据算法配置验证参数
      let verifyParams;
      if (algorithm === 'RSA-PSS') {
        verifyParams = {
          name: 'RSA-PSS',
          saltLength: 32, // 盐长度等于哈希长度
        };
      } else {
        verifyParams = {
          name: 'RSASSA-PKCS1-v1_5'
        };
      }

      // 验证签名
      const isValid = await crypto.subtle.verify(
        verifyParams,
        publicKey,
        signatureBuffer,
        this.textEncoder.encode(message)
      );

      return {
        success: true,
        valid: isValid,
        message: message,
        algorithm: algorithm,
        hashAlgorithm: 'SHA-256'
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
        valid: false
      };
    }
  }

  // ===== 安全功能 =====

  /**
   * 清理敏感数据
   * @param {string} elementId - 要清理的元素ID
   * @param {number} overwriteCount - 覆写次数，默认3次
   */
  clearSensitiveData(elementId, overwriteCount = 3) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const originalLength = element.value ? element.value.length : 0;
    if (originalLength === 0) return;

    // 多次覆写以确保数据安全清除
    for (let i = 0; i < overwriteCount; i++) {
      element.value = '0'.repeat(originalLength);
      element.value = '1'.repeat(originalLength);
      element.value = 'X'.repeat(originalLength);
    }
    element.value = '';
  }

  /**
   * 生成安全的随机密码
   * @param {number} length - 密码长度
   * @param {boolean} includeSpecial - 是否包含特殊字符
   * @returns {string} 随机密码
   */
  generateSecurePassword(length = 16, includeSpecial = true) {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    let charset = lowercase + uppercase + numbers;
    if (includeSpecial) {
      charset += special;
    }
    
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    
    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset[array[i] % charset.length];
    }
    
    return password;
  }

  /**
   * 验证密码强度
   * @param {string} password - 要验证的密码
   * @returns {Object} 密码强度信息
   */
  checkPasswordStrength(password) {
    const checks = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      numbers: /\d/.test(password),
      special: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)
    };
    
    const score = Object.values(checks).filter(Boolean).length;
    let strength = '弱';
    let color = '#dc3545';
    
    if (score >= 4) {
      strength = '强';
      color = '#28a745';
    } else if (score >= 3) {
      strength = '中';
      color = '#ffc107';
    }
    
    return {
      strength,
      color,
      score,
      checks,
      suggestions: this.getPasswordSuggestions(checks)
    };
  }

  /**
   * 获取密码改进建议
   */
  getPasswordSuggestions(checks) {
    const suggestions = [];
    if (!checks.length) suggestions.push('密码至少8位字符');
    if (!checks.uppercase) suggestions.push('添加大写字母');
    if (!checks.lowercase) suggestions.push('添加小写字母');
    if (!checks.numbers) suggestions.push('添加数字');
    if (!checks.special) suggestions.push('添加特殊字符');
    return suggestions;
  }
}

// 创建全局实例
const cryptoUtils = new CryptoUtils();
