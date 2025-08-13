/**
 * KeyExchangeService - Handles RSA key exchange and management with enhanced validation and caching
 * All operations now use the actual GitHub username (lowercase) instead of numeric DB IDs.
 */

class KeyExchangeService {
  constructor() {
    this.userKeys = new Map(); // Cache for user public keys with metadata
    this.keyVersions = new Map(); // Track key versions for rotation
    this.myPrivateKey = null;
    this.myPublicKey = null;
    this.myKeyVersion = 1;
    this.cacheExpiry = 30 * 60 * 1000; // 30 minutes cache expiry
    this.maxRetries = 3;
    this.BACKEND_URL = "http://localhost:5000";
  }

  /**
   * Normalize GitHub username to lowercase
   */
  _normalizeUsername(username) {
    if (!username || typeof username !== 'string') {
      throw new Error("GitHub username is required");
    }
    return username.trim().toLowerCase();
  }

  /**
   * Initialize keys and upload to GitHub
   */
  async initializeKeys(githubUsername, githubToken) {
    githubUsername = this._normalizeUsername(githubUsername);
    console.log(' [KEY_INIT] Starting GitHub-based key initialization for user:', githubUsername);

    try {
      const keyStorageService = (await import('./keyStorageService.js')).default;

      // Try existing private key
      const existingPrivateKey = await keyStorageService.getPrivateKey(githubUsername);
      if (existingPrivateKey && await this.validateKeyPair(null, existingPrivateKey)) {
        console.log(' [KEY_INIT]  Using existing private key');
        this.myPrivateKey = existingPrivateKey;
        return true;
      }

      // Generate new RSA key pair
      console.log(' [KEY_INIT]  Generating new RSA key pair...');
      const CryptoService = (await import('./cryptoService.js')).default;
      const keyPair = await CryptoService.generateRSAKeyPair();

      this.myPrivateKey = keyPair.privateKey;
      this.myPublicKey = keyPair.publicKey;

      // Store private key locally under GitHub username
      await keyStorageService.storePrivateKey(githubUsername, this.myPrivateKey);
      console.log(' [KEY_INIT]  Private key stored locally');

      // Upload public key to GitHub
      if (githubToken) {
        const githubKeyService = (await import('./gitHubService.js')).default;
        await githubKeyService.uploadPublicKey(keyPair.publicKey, githubToken);
        console.log(' [KEY_INIT]  Public key uploaded to GitHub');
      }

      console.log('[KEY_INIT]  GitHub-based key initialization completed!');
      return true;

    } catch (error) {
      console.error(' [KEY_INIT]  Failed to initialize keys:', error);
      throw error;
    }
  }

  /**
   * Get public key for a specific GitHub user from GitHub
   */
  async getUserPublicKey(githubUsername) {
    githubUsername = this._normalizeUsername(githubUsername);
    console.log(' [KEY_FETCH] Fetching public key from GitHub for:', githubUsername);

    try {
      const githubKeyService = (await import('./gitHubService.js')).default;

      // Fetch SSH keys from GitHub
      const sshKeys = await githubKeyService.fetchUserPublicKeys(githubUsername);
      if (!sshKeys || sshKeys.length === 0) {
        throw new Error(`No public keys found for GitHub user: ${githubUsername}`);
      }

      // Convert first SSH key to PEM format
      const pemKey = githubKeyService.convertSSHtoPEM(sshKeys[0]);

      console.log(' [KEY_FETCH]  Public key fetched from GitHub successfully');
      return pemKey;

    } catch (error) {
      console.error('[KEY_FETCH] Failed to get GitHub public key:', error);
      throw error;
    }
  }

  /**
   * Get all public keys for GitHub users in a room
   */
  async getRoomUserKeys(githubUsernames) {
    const keys = {};
    for (const username of githubUsernames) {
      try {
        keys[username] = await this.getUserPublicKey(username);
      } catch (error) {
        console.warn(`Failed to get key for GitHub user ${username}:`, error);
      }
    }
    return keys;
  }

  getMyPrivateKey() {
    return this.myPrivateKey;
  }

  getMyPublicKey() {
    return this.myPublicKey;
  }

  getMyKeyVersion() {
    return this.myKeyVersion || 1;
  }

  /**
   * Refresh a user's public key from GitHub
   */
  async refreshUserKey(githubUsername) {
    githubUsername = this._normalizeUsername(githubUsername);
    try {
      this.userKeys.delete(githubUsername);
      this.keyVersions.delete(githubUsername);
      const publicKey = await this.getUserPublicKey(githubUsername);
      console.log(`Refreshed public key for GitHub user ${githubUsername}`);
      return publicKey;
    } catch (error) {
      console.error(`Failed to refresh key for GitHub user ${githubUsername}:`, error);
      throw error;
    }
  }

  /**
   * Validate RSA key pair
   */
  async validateKeyPair(publicKey, privateKey) {
    try {
      if (!privateKey) return false;
      if (!this._isValidPrivateKey(privateKey)) return false;
      if (publicKey && !this._isValidPublicKey(publicKey)) return false;

      const CryptoService = (await import("./cryptoService.js")).default;
      const testData = "key_validation_test_" + Date.now();

      try {
        const signature = await CryptoService.signWithRSA(testData, privateKey);
        if (!signature) return false;

        if (publicKey) {
          const isValidSignature = await CryptoService.verifyRSASignature(testData, signature, publicKey);
          if (!isValidSignature) return false;

          const encrypted = await CryptoService.encryptWithRSA(testData, publicKey);
          const decrypted = await CryptoService.decryptWithRSA(encrypted, privateKey);
          if (decrypted !== testData) return false;
        }
        return true;
      } catch (error) {
        console.warn("Key pair functional validation failed:", error);
        return false;
      }
    } catch (error) {
      console.error("Key pair validation error:", error);
      return false;
    }
  }

  /**
   * Rotate keys for the current GitHub user
   */
  async rotateMyKeys(githubUsername, githubToken) {
    githubUsername = this._normalizeUsername(githubUsername);
    try {
      console.log(`Starting key rotation for user ${githubUsername}`);

      this.myPrivateKey = null;
      this.myPublicKey = null;

      const keyStorageService = (await import('./keyStorageService.js')).default;
      await keyStorageService.clearPrivateKey(githubUsername);

      await this.initializeKeys(githubUsername, githubToken);

      console.log(`Key rotation completed for user ${githubUsername}`);
      return true;
    } catch (error) {
      console.error(`Failed to rotate keys for user ${githubUsername}:`, error);
      throw error;
    }
  }

  clearCache() {
    this.userKeys.clear();
    this.keyVersions.clear();
  }

  async clearAllKeys() {
    try {
      this.clearCache();
      const keyStorageService = (await import("./keyStorageService.js")).default;
      await keyStorageService.clearAllKeys();
      this.myPrivateKey = null;
      this.myPublicKey = null;
      this.myKeyVersion = 1;
      console.log("All keys cleared successfully");
    } catch (error) {
      console.error("Failed to clear all keys:", error);
      throw error;
    }
  }

  _isValidPublicKey(publicKey) {
    if (!publicKey || typeof publicKey !== 'string') return false;
    const pemRegex = /^-----BEGIN PUBLIC KEY-----[\s\S]*-----END PUBLIC KEY-----$/;
    return pemRegex.test(publicKey.trim());
  }

  _isValidPrivateKey(privateKey) {
    if (!privateKey || typeof privateKey !== 'string') return false;
    const pkcs1Regex = /^-----BEGIN RSA PRIVATE KEY-----[\s\S]*-----END RSA PRIVATE KEY-----$/;
    const pkcs8Regex = /^-----BEGIN PRIVATE KEY-----[\s\S]*-----END PRIVATE KEY-----$/;
    return pkcs1Regex.test(privateKey.trim()) || pkcs8Regex.test(privateKey.trim());
  }
}

const keyExchangeService = new KeyExchangeService();
export default keyExchangeService;
