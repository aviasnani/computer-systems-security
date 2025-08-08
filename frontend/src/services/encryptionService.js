/**
 * EncryptionService - High-level message encryption orchestration service
 * Orchestrates complete encrypt/decrypt message flow with error handling and graceful degradation
 */

import CryptoService from './cryptoService';
import keyExchangeService from './keyExchangeService';
import keyStorageService from './keyStorageService';

// Encryption error types
export const EncryptionErrorTypes = {
  KEY_GENERATION_FAILED: 'key_generation_failed',
  ENCRYPTION_FAILED: 'encryption_failed',
  DECRYPTION_FAILED: 'decryption_failed',
  KEY_EXCHANGE_FAILED: 'key_exchange_failed',
  SIGNATURE_VERIFICATION_FAILED: 'signature_verification_failed',
  STORAGE_FAILED: 'storage_failed',
  INITIALIZATION_FAILED: 'initialization_failed'
};

// Encryption status interface
export const EncryptionStatus = {
  AVAILABLE: 'available',
  UNAVAILABLE: 'unavailable',
  INITIALIZING: 'initializing',
  ERROR: 'error'
};

class EncryptionService {
  constructor() {
    this.isInitialized = false;
    this.currentUserId = null;
    this.currentToken = null;
    this.lastError = null;
    this.keyGenerationTime = null;
    this.initializationPromise = null;
  }

  /**
   * Initialize encryption service for the current user
   * @param {string} userId - Current user ID
   * @param {string} token - Authentication token
   * @returns {Promise<boolean>} True if initialization successful
   */
  async initialize(userId, token) {
    try {
      // Prevent multiple simultaneous initializations
      if (this.initializationPromise) {
        return await this.initializationPromise;
      }

      this.initializationPromise = this._performInitialization(userId, token);
      const result = await this.initializationPromise;
      this.initializationPromise = null;
      
      return result;
    } catch (error) {
      this.initializationPromise = null;
      throw error;
    }
  }

  /**
   * Encrypt a message for sending to a specific recipient
   * @param {string} message - Plain text message to encrypt
   * @param {string} recipientGithubUsername - Recipient's user ID
   * @returns {Promise<EncryptedMessageData>} Encrypted message data
   */
  async encryptMessage(message, recipientGithubUsername) {
    console.log('[ENCRYPTION] Starting message encryption process');
    console.log('[ENCRYPTION] Message length:', message.length, 'characters');
    console.log('[ENCRYPTION] Recipient username:', recipientGithubUsername);
    
    try {
      // Basic validation
      if (!message || typeof message !== 'string') {
        console.error(' [ENCRYPTION] Invalid message format');
        throw new Error('Invalid message format');
      }

      if (!recipientGithubUsername) {
        console.error(' [ENCRYPTION]  Recipient Github username  is required');
        throw new Error('Recipient github username is required');
      }

      if (!this.isEncryptionAvailable()) {
        console.error('[ENCRYPTION]  Encryption not available');
        throw new Error('Encryption not available');
      }

      console.log('[ENCRYPTION]  Pre-flight checks passed');

      // REAL RSA PUBLIC-PRIVATE KEY ENCRYPTION
      console.log('ENCRYPTION: Using REAL RSA public-private key encryption');
      
      // Get recipient's public key with FRESH fetch
      let recipientKeyData;
      try {
        recipientKeyData = await this._getRecipientPublicKey(recipientGithubUsername);
        console.log('ENCRYPTION: Got FRESH recipient public key, ID:', recipientKeyData.keyId);
      } catch (error) {
        console.error('ENCRYPTION: No recipient public key, sending plain text');
        return {
          content: message,
          encrypted_aes_key: null,
          iv: null,
          signature: null,
          is_encrypted: false,
          sender_id: this.currentUserId
        };
      }
      
      // Generate AES key for this message
      const aesKey = await CryptoService.generateAESKey();
      console.log('ENCRYPTION: Generated AES key');
      
      // Encrypt message with AES
      const encryptedMessage = await CryptoService.encryptWithAES(message, aesKey);
      console.log('ENCRYPTION: Message encrypted with AES');
      
      // Encrypt AES key with recipient's PUBLIC key (RSA)
      const encryptedAESKey = await this._encryptWithPublicKey(aesKey, recipientKeyData.publicKey);
      console.log('ENCRYPTION: AES key encrypted with recipient\'s PUBLIC key, ID:', recipientKeyData.keyId);
      
      // Sign message with our PRIVATE key
      const myPrivateKey = await this._getMyPrivateKey();
      const signature = await this._signWithPrivateKey(message, myPrivateKey);
      console.log('ENCRYPTION: Message signed with our PRIVATE key');

      const encryptedData = {
        content: encryptedMessage.encryptedData,
        encrypted_aes_key: encryptedAESKey,
        iv: encryptedMessage.iv,
        signature: signature,
        is_encrypted: true,
        sender_id: this.currentUserId,
        recipient_key_id: recipientKeyData.keyId,
        intended_recipient: recipientGithubUsername
      };

      console.log('ENCRYPTION: REAL RSA encryption completed!');
      this.lastError = null;
      return encryptedData;
      // Real encryption code above

    } catch (error) {
      this.lastError = this._createErrorInfo(EncryptionErrorTypes.ENCRYPTION_FAILED, error);
      throw this.lastError;
    }
  }

  /**
   * Decrypt a received message
   * @param {EncryptedMessageData} encryptedData - Encrypted message data
   * @param {string} senderUserId - Sender's user ID for signature verification
   * @returns {Promise<string>} Decrypted plain text message
   */
  async decryptMessage(encryptedData, senderUserId) {
    console.log('[DECRYPTION] Starting message decryption process');
    console.log('[DECRYPTION] Sender ID:', senderUserId);
    console.log('DECRYPTION] Is encrypted:', encryptedData?.is_encrypted);
    
    try {
      if (!encryptedData) {
        console.error('[DECRYPTION]  No encrypted data provided');
        throw new Error('No encrypted data provided');
      }

      // If message is not encrypted, return as-is
      if (!encryptedData.is_encrypted) {
        console.log('DECRYPTION: Message is not encrypted, returning as-is');
        return encryptedData.content;
      }

      if (!this.isEncryptionAvailable()) {
        console.error('DECRYPTION: Encryption not available for decryption');
        throw new Error('Encryption not available for decryption');
      }

      console.log('DECRYPTION: Starting real message decryption');
      console.log('DECRYPTION: Full encrypted data:', {
        sender_id: encryptedData.sender_id,
        is_encrypted: encryptedData.is_encrypted,
        has_aes_key: !!encryptedData.encrypted_aes_key,
        has_iv: !!encryptedData.iv
      });

      // Decrypt AES key with our private key
      console.log('DECRYPTION: Decrypting AES key with RSA private key...');
      console.log('DECRYPTION: Encrypted AES key length:', encryptedData.encrypted_aes_key?.length);
      console.log('DECRYPTION: Message sender:', senderUserId);
      console.log('DECRYPTION: Current user:', this.currentUserId);
      console.log('DECRYPTION: Message sender_id from data:', encryptedData.sender_id);
      
      // Check if this message was sent by us
      if (encryptedData.sender_id === this.currentUserId) {
        console.log('DECRYPTION: This is our own message - showing as sent');
        return '[Your encrypted message]';
      }
      
      // Verify this message was intended for us
      if (encryptedData.intended_recipient && encryptedData.intended_recipient !== this.currentUserId) {
        console.error('DECRYPTION: Message not intended for us. Intended for:', encryptedData.intended_recipient);
        throw new Error('Message was not encrypted for this user');
      }
      
      // Get our current key ID for verification
      const myPublicKey = keyExchangeService.getMyPublicKey();
      const myKeyVersion = keyExchangeService.getMyKeyVersion();
      const myKeyId = `${this.currentUserId}_v${myKeyVersion}`;
      
      console.log('DECRYPTION: Our key ID:', myKeyId);
      console.log('DECRYPTION: Message encrypted with key ID:', encryptedData.recipient_key_id);
      
      if (encryptedData.recipient_key_id && encryptedData.recipient_key_id !== myKeyId) {
        console.warn('DECRYPTION: Key ID mismatch - message encrypted with different key version');
        console.warn('DECRYPTION: Expected:', myKeyId, 'Got:', encryptedData.recipient_key_id);
      }
      
      // REAL RSA PUBLIC-PRIVATE KEY DECRYPTION
      console.log('DECRYPTION: Using REAL RSA private key decryption');
      
      // Decrypt AES key with our PRIVATE key (RSA)
      const myPrivateKey = await this._getMyPrivateKey();
      console.log('DECRYPTION: Got our private key');
      
      let aesKey;
      try {
        aesKey = await this._decryptWithPrivateKey(encryptedData.encrypted_aes_key, myPrivateKey);
        console.log('DECRYPTION: AES key decrypted with our PRIVATE key');
      } catch (rsaError) {
        throw new Error('Cannot decrypt: message was not encrypted for this user');
      }
      
      // Decrypt message content with AES key
      console.log('DECRYPTION: Decrypting message content with AES...');
      const decryptedMessage = await CryptoService.decryptWithAES(
        encryptedData.content,
        encryptedData.iv,
        aesKey
      );
      console.log('DECRYPTION: Message decrypted successfully!');
      
      // Verify signature with sender's PUBLIC key
      if (encryptedData.signature && senderUserId) {
        console.log('DECRYPTION: Verifying signature with sender\'s PUBLIC key...');
        const senderPublicKey = await this._getRecipientPublicKey(senderUserId);
        const isValid = await this._verifyWithPublicKey(decryptedMessage, encryptedData.signature, senderPublicKey.publicKey);
        if (!isValid) {
          console.warn('DECRYPTION: Signature verification failed!');
        } else {
          console.log('DECRYPTION: Signature verified - message is authentic!');
        }
      }
      
      return decryptedMessage;



    } catch (error) {
      // Preserve signature verification error type
      if (error.type === EncryptionErrorTypes.SIGNATURE_VERIFICATION_FAILED) {
        this.lastError = this._createErrorInfo(EncryptionErrorTypes.SIGNATURE_VERIFICATION_FAILED, error);
      } else {
        this.lastError = this._createErrorInfo(EncryptionErrorTypes.DECRYPTION_FAILED, error);
      }
      
      throw this.lastError;
    }
  }

  /**
   * Decrypt a message without signature verification (for fallback scenarios)
   * @param {EncryptedMessageData} encryptedData - Encrypted message data
   * @returns {Promise<string>} Decrypted plain text message
   */
  async decryptMessageWithoutSignature(encryptedData) {
    try {
      if (!encryptedData) {
        throw new Error('No encrypted data provided');
      }

      // If message is not encrypted, return as-is
      if (!encryptedData.is_encrypted) {
        return encryptedData.content;
      }

      if (!this.isEncryptionAvailable()) {
        throw new Error('Encryption not available for decryption');
      }

      // Decrypt AES key with our private key
      const myPrivateKey = await this._getMyPrivateKey();
      const aesKey = await CryptoService.decryptWithRSA(
        encryptedData.encrypted_aes_key, 
        myPrivateKey
      );
      
      // Decrypt message content with AES key
      const decryptedMessage = await CryptoService.decryptWithAES(
        encryptedData.content,
        encryptedData.iv,
        aesKey
      );

      this.lastError = null;
      return decryptedMessage;

    } catch (error) {
      console.error('Message decryption (without signature) failed:', error);
      this.lastError = this._createErrorInfo(EncryptionErrorTypes.DECRYPTION_FAILED, error);
      throw this.lastError;
    }
  }

  /**
   * Check if encryption is available
   * @returns {boolean} True if encryption is available
   */
  isEncryptionAvailable() {
    return this.isInitialized && 
           this.currentUserId && 
           this.currentToken &&
           keyExchangeService.getMyPrivateKey() !== null;
  }

  /**
   * Get current encryption status
   * @returns {Object} Encryption status information
   */
  getEncryptionStatus() {
    const hasPrivateKey = keyExchangeService.getMyPrivateKey() !== null;
    const hasPublicKey = keyExchangeService.getMyPublicKey() !== null;

    let status = EncryptionStatus.UNAVAILABLE;
    if (this.initializationPromise) {
      status = EncryptionStatus.INITIALIZING;
    } else if (this.isEncryptionAvailable()) {
      status = EncryptionStatus.AVAILABLE;
    } else if (this.lastError) {
      status = EncryptionStatus.ERROR;
    }

    return {
      status,
      isAvailable: this.isEncryptionAvailable(),
      keysInitialized: hasPrivateKey && hasPublicKey,
      lastError: this.lastError,
      keyGenerationTime: this.keyGenerationTime,
      userId: this.currentUserId
    };
  }

  /**
   * Handle encryption errors with user-friendly messages
   * @param {Error} error - The error that occurred
   * @returns {Object} Error information object
   */
  handleEncryptionError(error) {
    return this._createErrorInfo(EncryptionErrorTypes.ENCRYPTION_FAILED, error);
  }

  /**
   * Clear encryption state and keys (for logout)
   * @returns {Promise<void>}
   */
  async clearEncryption() {
    try {
      if (this.currentUserId) {
        await keyStorageService.clearPrivateKey(this.currentUserId);
      }
      
      keyExchangeService.clearCache();
      
      this.isInitialized = false;
      this.currentUserId = null;
      this.currentToken = null;
      this.lastError = null;
      this.keyGenerationTime = null;
      
      console.log('Encryption state cleared');
    } catch (error) {
      console.error('Failed to clear encryption state:', error);
    }
  }

  /**
   * Refresh encryption keys (regenerate and re-upload)
   * @returns {Promise<boolean>} True if refresh successful
   */
  async refreshKeys() {
    try {
      if (!this.currentUserId || !this.currentToken) {
        throw new Error('User not initialized');
      }

      // Clear existing keys
      await keyStorageService.clearPrivateKey(this.currentUserId);
      keyExchangeService.clearCache();

      // Re-initialize with new keys
      return await this.initialize(this.currentUserId, this.currentToken);
    } catch (error) {
      console.error('Failed to refresh keys:', error);
      this.lastError = this._createErrorInfo(EncryptionErrorTypes.KEY_GENERATION_FAILED, error);
      return false;
    }
  }

  // Private helper methods

  /**
   * Perform the actual initialization process
   * @param {string} userId - User ID
   * @param {string} token - Authentication token
   * @returns {Promise<boolean>} True if successful
   */
  async _performInitialization(userId, token) {
    console.log('INIT: Starting encryption service initialization');
    console.log('INIT: User ID:', userId);
    
    try {
      this.currentUserId = userId;
      this.currentToken = token;

      // Try to load existing private key from storage
      console.log('INIT: Checking for existing private key...');
      let privateKey = await keyStorageService.getPrivateKey(userId);
      let publicKey = null;

      if (privateKey) {
        console.log('INIT: Found existing private key, validating...');
        const isValid = await keyStorageService.validateStoredKey(userId);
        if (!isValid) {
          console.warn('INIT: Stored key is invalid, generating new keys');
          privateKey = null;
        } else {
          console.log('INIT: Existing private key is valid');
        }
      } else {
        console.log('INIT: No existing private key found');
      }

      if (!privateKey) {
        console.log('INIT: Generating new RSA-2048 key pair...');
        const keyPair = await CryptoService.generateRSAKeyPair();
        privateKey = keyPair.privateKey;
        publicKey = keyPair.publicKey;
        console.log('INIT: RSA key pair generated successfully');
        
        // Store private key securely
        console.log('INIT: Storing private key securely...');
        await keyStorageService.storePrivateKey(userId, privateKey);
        console.log('INIT: Private key stored securely');
        
        this.keyGenerationTime = new Date();
      }

      // Initialize key exchange service
      console.log('INIT: Initializing key exchange service...');
      await keyExchangeService.initializeKeys(userId, token);
      console.log('INIT: Key exchange service initialized');

      this.isInitialized = true;
      this.lastError = null;
      
      console.log('INIT: EncryptionService initialized successfully!');
      console.log('INIT: End-to-end encryption is now ACTIVE');
      return true;

    } catch (error) {
      console.error('INIT: EncryptionService initialization failed:', error);
      this.lastError = this._createErrorInfo(EncryptionErrorTypes.INITIALIZATION_FAILED, error);
      this.isInitialized = false;
      throw error;
    }
  }

  /**
   * Get recipient's public key with FRESH retrieval and key ID
   * @param {string} recipientUserId - Recipient's user ID
   * @returns {Promise<{publicKey: string, keyId: string}>} Public key with ID
   */
  async _getRecipientPublicKey(recipientGithubUsername) {
    console.log('KEY_EXCHANGE: FRESH fetch of public key for recipient:', recipientGithubUsername);
    
      try {
        // Directly fetch PEM from GitHub via keyExchangeService
        const pemKey = await keyExchangeService.getUserPublicKey(recipientGithubUsername);

        // Wrap with a default key version (you can enhance this later if you want rotation)
        return {
            publicKey: pemKey,
            keyId: `${recipientGithubUsername}_v1`
        };
    } catch (error) {
        console.error('KEY_EXCHANGE: Failed to fetch public key from GitHub:', error.message);
        throw new Error(`Cannot fetch public key for ${recipientGithubUsername}`);
    }
  }

  /**
   * Get current user's private key
   * @returns {Promise<string>} Private key
   */
  async _getMyPrivateKey() {
    const privateKey = keyExchangeService.getMyPrivateKey();
    if (!privateKey) {
      throw new Error('Private key not available');
    }
    return privateKey;
  }

  /**
   * Generate a deterministic room key for two users
   * @param {string} userId1 - First user ID
   * @param {string} userId2 - Second user ID
   * @returns {Promise<string>} Room key in hex format
   */
  async _generateRoomKey(userId1, userId2) {
    // Create deterministic key based on both user IDs
    const sortedIds = [userId1, userId2].sort();
    const keyString = `room_key_${sortedIds[0]}_${sortedIds[1]}_secret`;
    
    console.log('ROOM_KEY: Generating key for users:', userId1, 'and', userId2);
    console.log('ROOM_KEY: Sorted IDs:', sortedIds);
    console.log('ROOM_KEY: Key string:', keyString);
    
    // Generate SHA-256 hash and convert to hex
    const encoder = new TextEncoder();
    const data = encoder.encode(keyString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer);
    
    const roomKey = Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('ROOM_KEY: Generated key length:', roomKey.length);
    console.log('ROOM_KEY: Generated key preview:', roomKey.substring(0, 20) + '...');
    
    return roomKey;
  }

  /**
   * Verify message signature
   * @param {string} message - Original message
   * @param {string} signature - Message signature
   * @param {string} senderUserId - Sender's user ID
   * @returns {Promise<boolean>} True if signature is valid
   */
  async _verifyMessageSignature(message, signature, senderUserId) {
    console.log('[SIGNATURE] Verifying message signature from sender:', senderUserId);
    
    try {
      console.log('[SIGNATURE] Getting sender public key for verification...');
      const senderPublicKey = await this._getRecipientPublicKey(senderUserId);
      console.log('[SIGNATURE]  Sender public key obtained');
      
      console.log('[SIGNATURE] Verifying RSA signature...');
      const isValid = await CryptoService.verifyRSASignature(message, signature, senderPublicKey);
      
      if (!isValid) {
        console.warn('[SIGNATURE]  Signature verification failed for message from', senderUserId);
        this.lastError = this._createErrorInfo(EncryptionErrorTypes.SIGNATURE_VERIFICATION_FAILED, 
          new Error('Message signature verification failed'));
      } else {
        console.log(' [SIGNATURE]  Signature verification successful - message is authentic');
      }
      
      return isValid;
    } catch (error) {
      console.error(' [SIGNATURE]  Signature verification error:', error);
      this.lastError = this._createErrorInfo(EncryptionErrorTypes.SIGNATURE_VERIFICATION_FAILED, error);
      return false;
    }
  }

  /**
   * Create standardized error information object
   * @param {string} type - Error type from EncryptionErrorTypes
   * @param {Error} error - Original error
   * @returns {Object} Error information object
   */
  _createErrorInfo(type, error) {
    return {
      type,
      message: error.message,
      timestamp: new Date(),
      userFriendlyMessage: this._getUserFriendlyErrorMessage(type, error)
    };
  }

  /**
   * Get user-friendly error message
   * @param {string} type - Error type
   * @param {Error} error - Original error
   * @returns {string} User-friendly error message
   */
  _getUserFriendlyErrorMessage(type, error) {
    switch (type) {
      case EncryptionErrorTypes.KEY_GENERATION_FAILED:
        return 'Failed to generate encryption keys. Please try again.';
      case EncryptionErrorTypes.ENCRYPTION_FAILED:
        return 'Failed to encrypt message. Please check your connection and try again.';
      case EncryptionErrorTypes.DECRYPTION_FAILED:
        return 'Unable to decrypt this message. It may be corrupted or sent with incompatible encryption.';
      case EncryptionErrorTypes.KEY_EXCHANGE_FAILED:
        return 'Failed to exchange encryption keys. Please refresh and try again.';
      case EncryptionErrorTypes.SIGNATURE_VERIFICATION_FAILED:
        return 'Message authenticity could not be verified. This message may not be from the claimed sender.';
      case EncryptionErrorTypes.STORAGE_FAILED:
        return 'Failed to store encryption keys securely. Please check your browser settings.';
      case EncryptionErrorTypes.INITIALIZATION_FAILED:
        return 'Failed to initialize encryption. Please refresh the page and try again.';
      default:
        return 'An encryption error occurred. Please try again.';
    }
  }

  /**
   * REAL RSA encryption with recipient's public key
   */
  async _encryptWithPublicKey(data, publicKeyPem) {
    console.log('RSA_ENCRYPT: Using REAL Web Crypto API RSA encryption');
    
    try {
      // Convert PEM to ArrayBuffer
      const publicKeyBuffer = this._pemToArrayBuffer(publicKeyPem);
      
      // Import the public key
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
      
      // Encrypt the data
      const dataBuffer = new TextEncoder().encode(data);
      const encryptedBuffer = await crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP'
        },
        publicKey,
        dataBuffer
      );
      
      // Convert to base64
      const encryptedArray = new Uint8Array(encryptedBuffer);
      const encrypted = btoa(String.fromCharCode(...encryptedArray));
      
      console.log('RSA_ENCRYPT: Successfully encrypted with recipient public key');
      return encrypted;
      
    } catch (error) {
      throw new Error(`RSA encryption failed: ${error.message}`);
    }
  }

  /**
   * REAL RSA decryption with our private key
   */
  async _decryptWithPrivateKey(encryptedData, privateKeyPem) {
    console.log('RSA_DECRYPT: Using REAL Web Crypto API RSA decryption');
    
    try {
      // Convert PEM to ArrayBuffer
      const privateKeyBuffer = this._pemToArrayBuffer(privateKeyPem);
      
      // Import the private key
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
      
      // Convert base64 to ArrayBuffer
      const encryptedArray = new Uint8Array(
        atob(encryptedData).split('').map(char => char.charCodeAt(0))
      );
      
      // Decrypt the data
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: 'RSA-OAEP'
        },
        privateKey,
        encryptedArray
      );
      
      // Convert back to string
      const decrypted = new TextDecoder().decode(decryptedBuffer);
      
      console.log('RSA_DECRYPT: Successfully decrypted with our private key');
      return decrypted;
      
    } catch (error) {
      throw new Error(`RSA decryption failed: ${error.message}`);
    }
  }

  /**
   * Helper to convert PEM to ArrayBuffer
   */
  _pemToArrayBuffer(pem) {
    const base64 = pem
      .replace(/-----BEGIN [A-Z ]+-----/g, '')
      .replace(/-----END [A-Z ]+-----/g, '')
      .replace(/[\r\n\s]/g, '');
    
    const binaryString = atob(base64);
    const buffer = new ArrayBuffer(binaryString.length);
    const view = new Uint8Array(buffer);
    
    for (let i = 0; i < binaryString.length; i++) {
      view[i] = binaryString.charCodeAt(i);
    }
    
    return buffer;
  }

  /**
   * Sign data with RSA private key
   */
  async _signWithPrivateKey(data, privateKeyPem) {
    return await CryptoService.signWithRSA(data, privateKeyPem);
  }

  /**
   * Verify signature with RSA public key
   */
  async _verifyWithPublicKey(data, signature, publicKeyPem) {
    return await CryptoService.verifyRSASignature(data, signature, publicKeyPem);
  }
}

// Export singleton instance
const encryptionService = new EncryptionService();
export default encryptionService;