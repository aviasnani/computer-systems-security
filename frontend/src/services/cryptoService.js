class CryptoService {
  // Generate RSA key pair using Web Crypto API
  static async generateRSAKeyPair() {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
      );

      const publicKey = await window.crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
      );
      const privateKey = await window.crypto.subtle.exportKey(
        "pkcs8",
        keyPair.privateKey
      );

      return {
        publicKey: this.arrayBufferToBase64(publicKey),
        privateKey: this.arrayBufferToBase64(privateKey),
        keyPair,
      };
    } catch (error) {
      throw new Error(`RSA key generation failed: ${error.message}`);
    }
  }

  // Generate AES key
  static async generateAESKey() {
    try {
      const key = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );

      const exported = await window.crypto.subtle.exportKey("raw", key);
      return this.arrayBufferToBase64(exported);
    } catch (error) {
      throw new Error(`AES key generation failed: ${error.message}`);
    }
  }

  // Encrypt with RSA
  static async encryptWithRSA(data, publicKeyBase64) {
    try {
      const publicKey = await window.crypto.subtle.importKey(
        "spki",
        this.base64ToArrayBuffer(publicKeyBase64),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );

      const encrypted = await window.crypto.subtle.encrypt(
        "RSA-OAEP",
        publicKey,
        new TextEncoder().encode(data)
      );

      return this.arrayBufferToBase64(encrypted);
    } catch (error) {
      throw new Error(`RSA encryption failed: ${error.message}`);
    }
  }

  // Decrypt with RSA
  static async decryptWithRSA(encryptedData, privateKeyBase64) {
    try {
      const privateKey = await window.crypto.subtle.importKey(
        "pkcs8",
        this.base64ToArrayBuffer(privateKeyBase64),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
      );

      const decrypted = await window.crypto.subtle.decrypt(
        "RSA-OAEP",
        privateKey,
        this.base64ToArrayBuffer(encryptedData)
      );

      return new TextDecoder().decode(decrypted);
    } catch (error) {
      throw new Error(`RSA decryption failed: ${error.message}`);
    }
  }

  // Encrypt with AES
  static async encryptWithAES(message, aesKeyBase64) {
    try {
      const key = await window.crypto.subtle.importKey(
        "raw",
        this.base64ToArrayBuffer(aesKeyBase64),
        "AES-GCM",
        false,
        ["encrypt"]
      );

      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        new TextEncoder().encode(message)
      );

      return {
        encryptedData: this.arrayBufferToBase64(encrypted),
        iv: this.arrayBufferToBase64(iv),
      };
    } catch (error) {
      throw new Error(`AES encryption failed: ${error.message}`);
    }
  }

  // Decrypt with AES
  static async decryptWithAES(encryptedData, iv, aesKeyBase64) {
    try {
      const key = await window.crypto.subtle.importKey(
        "raw",
        this.base64ToArrayBuffer(aesKeyBase64),
        "AES-GCM",
        false,
        ["decrypt"]
      );

      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: this.base64ToArrayBuffer(iv) },
        key,
        this.base64ToArrayBuffer(encryptedData)
      );

      return new TextDecoder().decode(decrypted);
    } catch (error) {
      throw new Error(`AES decryption failed: ${error.message}`);
    }
  }

  // Hybrid encryption: Encrypt message with AES, then encrypt AES key with RSA
  static async encryptMessageForRecipients(message, recipientPublicKeys) {
    try {
      // Generate a random AES key for this message
      const aesKey = await this.generateAESKey();
      
      // Encrypt the message with AES
      const aesEncrypted = await this.encryptWithAES(message, aesKey);
      
      // Encrypt the AES key with each recipient's public key
      const encryptedAesKeys = {};
      for (const [userId, publicKey] of Object.entries(recipientPublicKeys)) {
        try {
          const encryptedKey = await this.encryptWithRSA(aesKey, publicKey);
          encryptedAesKeys[userId] = encryptedKey;
        } catch (error) {
          console.warn(`Failed to encrypt AES key for user ${userId}:`, error);
        }
      }
      
      return {
        encryptedContent: aesEncrypted.encryptedData,
        iv: aesEncrypted.iv,
        encryptedAesKeys,
        encryptionType: 'hybrid'
      };
    } catch (error) {
      throw new Error(`Hybrid encryption failed: ${error.message}`);
    }
  }

  // Decrypt message using hybrid encryption
  static async decryptMessage(encryptedMessage, privateKeyBase64) {
    try {
      const { encryptedContent, iv, encryptedAesKeys, encryptionType } = encryptedMessage;
      
      if (encryptionType !== 'hybrid') {
        throw new Error('Unsupported encryption type');
      }
      
      // Try to decrypt the AES key with our private key
      let aesKey = null;
      for (const encryptedKey of Object.values(encryptedAesKeys)) {
        try {
          aesKey = await this.decryptWithRSA(encryptedKey, privateKeyBase64);
          break; // Found our encrypted key
        } catch (error) {
          // Try next key
          continue;
        }
      }
      
      if (!aesKey) {
        throw new Error('Could not decrypt AES key with any available private key');
      }
      
      // Decrypt the message content with the AES key
      const decryptedMessage = await this.decryptWithAES(encryptedContent, iv, aesKey);
      
      return decryptedMessage;
    } catch (error) {
      throw new Error(`Message decryption failed: ${error.message}`);
    }
  }

  // Utility functions
  static arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  static base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

export default CryptoService;
