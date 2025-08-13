module.exports = {

"[externals]/next/dist/compiled/next-server/app-page-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-page-turbo.runtime.dev.js, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js", () => require("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js"));

module.exports = mod;
}}),
"[externals]/crypto [external] (crypto, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("crypto", () => require("crypto"));

module.exports = mod;
}}),
"[project]/src/services/cryptoService.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
/**
 * CryptoService - Web Crypto API and JSEncrypt wrapper for RSA and AES operations
 * Implements end-to-end encryption functionality for the chat application
 * Uses RSA-2048 for key exchange and AES-256-GCM for message encryption
 */ __turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$crypto$2d$js$2f$index$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/crypto-js/index.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$jsencrypt$2f$lib$2f$index$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$module__evaluation$3e$__ = __turbopack_context__.i("[project]/node_modules/jsencrypt/lib/index.js [app-ssr] (ecmascript) <module evaluation>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$jsencrypt$2f$lib$2f$index$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$locals$3e$__ = __turbopack_context__.i("[project]/node_modules/jsencrypt/lib/index.js [app-ssr] (ecmascript) <locals>");
;
;
class CryptoService {
    //Generate RSA key pair for initial key exchange
    static async generateRSAKeyPair() {
        try {
            console.log('Generating RSA-2048 key pair...');
            // Check if Web Crypto API is available
            if (!crypto || !crypto.subtle || !crypto.subtle.generateKey) {
                console.warn('Web Crypto API not available, using JSEncrypt fallback');
                return this._generateRSAKeyPairFallback();
            }
            // Generate RSA key pair with EXACT same parameters
            const keyPair = await crypto.subtle.generateKey({
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([
                    1,
                    0,
                    1
                ]),
                hash: 'SHA-256'
            }, true, [
                'encrypt',
                'decrypt'
            ]);
            const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
            const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
            const publicKeyPem = this._arrayBufferToPem(publicKeyBuffer, 'PUBLIC KEY');
            const privateKeyPem = this._arrayBufferToPem(privateKeyBuffer, 'PRIVATE KEY');
            console.log('RSA key pair generated successfully');
            console.log('Public key length:', publicKeyPem.length);
            console.log('Private key length:', privateKeyPem.length);
            return {
                publicKey: publicKeyPem,
                privateKey: privateKeyPem
            };
        } catch (error) {
            console.error('RSA key generation failed:', error);
            throw new Error(`Failed to generate RSA key pair: ${error.message}`);
        }
    }
    /**
     * Export RSA public key
     */ static async exportPublicKey(publicKey) {
        try {
            return publicKey; // Just return the PEM string directly - simpler!
        } catch (error) {
            throw new Error(`Failed to export public key: ${error.message}`);
        }
    }
    /**
     * Import RSA public key
     */ static async importPublicKey(publicKeyPem) {
        try {
            return publicKeyPem; // Just return the PEM string directly - simpler!
        } catch (error) {
            throw new Error(`Failed to import public key: ${error.message}`);
        }
    }
    /**
     * Encrypt data using RSA public key with Web Crypto API
     */ static async encryptWithRSA(data, publicKeyPem) {
        console.log('RSA Encryption Starting...');
        console.log('Data to encrypt:', JSON.stringify(data));
        console.log('Data length:', data?.length);
        console.log('Public key preview:', publicKeyPem?.substring(0, 150));
        console.log('Public key length:', publicKeyPem?.length);
        try {
            // Step 1: Validate input
            if (!data || !publicKeyPem) {
                throw new Error('Missing data or public key');
            }
            // Step 2: Import the public key
            console.log('Step 2: Importing public key...');
            let publicKey;
            try {
                publicKey = await this._importPublicKey(publicKeyPem);
                console.log('Public key imported successfully');
            } catch (importError) {
                console.error('Public key import failed:', importError);
                throw new Error(`Public key import failed: ${importError.message}`);
            }
            // Step 3: Prepare data
            console.log('Step 3: Preparing data buffer...');
            const dataBuffer = new TextEncoder().encode(data);
            console.log('Data buffer created, length:', dataBuffer.length);
            // Check data size limit (RSA-2048 can encrypt ~190 bytes with OAEP)
            if (dataBuffer.length > 190) {
                throw new Error(`Data too large: ${dataBuffer.length} bytes (max ~190 for RSA-2048 OAEP)`);
            }
            // Step 4: Encrypt
            console.log('Step 4: Encrypting with RSA-OAEP...');
            let encryptedBuffer;
            try {
                encryptedBuffer = await crypto.subtle.encrypt({
                    name: 'RSA-OAEP'
                }, publicKey, dataBuffer);
                console.log('Encryption completed, buffer length:', encryptedBuffer.byteLength);
            } catch (encryptError) {
                console.error('Encryption operation failed:', encryptError);
                throw new Error(`Encryption operation failed: ${encryptError.message}`);
            }
            // Step 5: Convert to base64
            console.log('Step 5: Converting to base64...');
            const encryptedArray = new Uint8Array(encryptedBuffer);
            const encrypted = btoa(String.fromCharCode(...encryptedArray));
            console.log('RSA encryption successful! Result length:', encrypted.length);
            return encrypted;
        } catch (error) {
            console.error('RSA Encryption FAILED:', {
                errorName: error.name,
                errorMessage: error.message,
                errorStack: error.stack,
                inputData: data,
                keyPreview: publicKeyPem?.substring(0, 100)
            });
            throw new Error(`Failed to encrypt with RSA: ${error.message || 'Unknown encryption error'}`);
        }
    }
    /**
     * Decrypt data using RSA private key with Web Crypto API
     */ static async decryptWithRSA(encryptedData, privateKeyPem) {
        try {
            console.log('RSA Decryption starting...');
            console.log('Encrypted data length:', encryptedData?.length);
            console.log('Private key length:', privateKeyPem?.length);
            // Import the private key
            const privateKey = await this._importPrivateKey(privateKeyPem);
            console.log('Private key imported successfully');
            // Convert base64 to ArrayBuffer
            let encryptedArray;
            try {
                const binaryString = atob(encryptedData);
                encryptedArray = new Uint8Array(binaryString.length);
                for(let i = 0; i < binaryString.length; i++){
                    encryptedArray[i] = binaryString.charCodeAt(i);
                }
                console.log('Encrypted data converted to array, length:', encryptedArray.length);
            } catch (b64Error) {
                console.error('Base64 decode failed:', b64Error);
                throw new Error(`Invalid base64 data: ${b64Error.message}`);
            }
            // Decrypt with RSA-OAEP
            console.log('Attempting RSA-OAEP decryption...');
            const decryptedBuffer = await crypto.subtle.decrypt({
                name: 'RSA-OAEP'
            }, privateKey, encryptedArray);
            // Convert back to string
            const decrypted = new TextDecoder().decode(decryptedBuffer);
            console.log('RSA decryption successful, result length:', decrypted.length);
            return decrypted;
        } catch (error) {
            console.error('RSA Decryption error:', error.name, error.message);
            throw new Error(`Failed to decrypt with RSA: ${error.message}`);
        }
    }
    /**
     * Sign data using RSA private key with Web Crypto API
     */ static async signWithRSA(data, privateKeyPem) {
        try {
            console.log('RSA Signing with Web Crypto API');
            // Import the private key for signing
            const buffer = this._pemToArrayBuffer(privateKeyPem);
            const privateKey = await crypto.subtle.importKey('pkcs8', buffer, {
                name: 'RSA-PSS',
                hash: 'SHA-256'
            }, false, [
                'sign'
            ]);
            // Sign the data
            const dataBuffer = new TextEncoder().encode(data);
            const signatureBuffer = await crypto.subtle.sign({
                name: 'RSA-PSS',
                saltLength: 32
            }, privateKey, dataBuffer);
            // Convert to base64
            const signatureArray = new Uint8Array(signatureBuffer);
            const signature = btoa(String.fromCharCode(...signatureArray));
            console.log('RSA signing successful');
            return signature;
        } catch (error) {
            console.error('RSA Signing error:', error);
            throw new Error(`Failed to sign with RSA: ${error.message}`);
        }
    }
    /**
     * Verify RSA signature using public key with Web Crypto API
     */ static async verifyRSASignature(data, signature, publicKeyPem) {
        try {
            console.log('RSA Signature verification with Web Crypto API');
            // Import the public key for verification
            const buffer = this._pemToArrayBuffer(publicKeyPem);
            const publicKey = await crypto.subtle.importKey('spki', buffer, {
                name: 'RSA-PSS',
                hash: 'SHA-256'
            }, false, [
                'verify'
            ]);
            // Convert signature from base64
            const signatureArray = new Uint8Array(atob(signature).split('').map((char)=>char.charCodeAt(0)));
            // Verify the signature
            const dataBuffer = new TextEncoder().encode(data);
            const isValid = await crypto.subtle.verify({
                name: 'RSA-PSS',
                saltLength: 32
            }, publicKey, signatureArray, dataBuffer);
            console.log('RSA signature verification result:', isValid);
            return isValid;
        } catch (error) {
            console.error('RSA Signature verification error:', error);
            return false;
        }
    }
    /**
     * Generate AES key for message encryption using Web Crypto API
     */ static async generateAESKey() {
        try {
            // Generate 256-bit AES key using Web Crypto API
            const key = await crypto.subtle.generateKey({
                name: 'AES-GCM',
                length: 256
            }, true, [
                'encrypt',
                'decrypt'
            ]);
            // Export key as raw bytes and convert to hex
            const keyBuffer = await crypto.subtle.exportKey('raw', key);
            const keyArray = new Uint8Array(keyBuffer);
            return Array.from(keyArray).map((b)=>b.toString(16).padStart(2, '0')).join('');
        } catch (error) {
            throw new Error(`Failed to generate AES key: ${error.message}`);
        }
    }
    /**
     * Encrypt message using AES-256-GCM with Web Crypto API
     */ static async encryptWithAES(message, aesKeyHex) {
        try {
            // Generate random IV for each message (96-bit IV for GCM)
            const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
            // Convert hex key to Uint8Array
            const keyBytes = new Uint8Array(aesKeyHex.match(/.{2}/g).map((byte)=>parseInt(byte, 16)));
            // Import the key
            const key = await crypto.subtle.importKey('raw', keyBytes, {
                name: 'AES-GCM'
            }, false, [
                'encrypt'
            ]);
            // Encrypt the message
            const messageBytes = new TextEncoder().encode(message);
            const encryptedBuffer = await crypto.subtle.encrypt({
                name: 'AES-GCM',
                iv: iv
            }, key, messageBytes);
            // Convert to base64 for storage/transmission
            const encryptedArray = new Uint8Array(encryptedBuffer);
            const encryptedBase64 = btoa(String.fromCharCode(...encryptedArray));
            const ivBase64 = btoa(String.fromCharCode(...iv));
            return {
                encryptedData: encryptedBase64,
                iv: ivBase64
            };
        } catch (error) {
            throw new Error(`Failed to encrypt with AES: ${error.message}`);
        }
    }
    /**
     * Decrypt message using AES-256-GCM with Web Crypto API
     */ static async decryptWithAES(encryptedData, ivB64, aesKeyHex) {
        try {
            // Convert base64 to Uint8Array
            const encryptedBytes = new Uint8Array(atob(encryptedData).split('').map((char)=>char.charCodeAt(0)));
            const iv = new Uint8Array(atob(ivB64).split('').map((char)=>char.charCodeAt(0)));
            // Convert hex key to Uint8Array
            const keyBytes = new Uint8Array(aesKeyHex.match(/.{2}/g).map((byte)=>parseInt(byte, 16)));
            // Import the key
            const key = await crypto.subtle.importKey('raw', keyBytes, {
                name: 'AES-GCM'
            }, false, [
                'decrypt'
            ]);
            // Decrypt the message
            const decryptedBuffer = await crypto.subtle.decrypt({
                name: 'AES-GCM',
                iv: iv
            }, key, encryptedBytes);
            // Convert back to string
            const decryptedMessage = new TextDecoder().decode(decryptedBuffer);
            if (!decryptedMessage) {
                throw new Error('AES decryption failed - invalid key or corrupted data');
            }
            return decryptedMessage;
        } catch (error) {
            throw new Error(`Failed to decrypt with AES: ${error.message}`);
        }
    }
    /**
     * Export AES key 
     */ static async exportAESKey(aesKeyHex) {
        try {
            return aesKeyHex; // Just return the hex string directly - simpler!
        } catch (error) {
            throw new Error(`Failed to export AES key: ${error.message}`);
        }
    }
    /**
     * Import AES key (accepts hex format directly for simplicity)
     */ static async importAESKey(aesKeyHex) {
        try {
            return aesKeyHex; // Just return the hex string directly - simpler!
        } catch (error) {
            throw new Error(`Failed to import AES key: ${error.message}`);
        }
    }
    /**
     * Export RSA private key
     */ static async exportPrivateKey(privateKey) {
        try {
            return privateKey; // Just return the PEM string directly - simpler!
        } catch (error) {
            throw new Error(`Failed to export private key: ${error.message}`);
        }
    }
    /**
     * Import RSA private key 
     */ static async importPrivateKey(privateKeyPem) {
        try {
            return privateKeyPem; // Just return the PEM string directly - simpler!
        } catch (error) {
            throw new Error(`Failed to import private key: ${error.message}`);
        }
    }
    // Helper methods for Web Crypto API
    static _arrayBufferToPem(buffer, type) {
        const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        const formatted = base64.match(/.{1,64}/g).join('\n');
        const pem = `-----BEGIN ${type}-----\n${formatted}\n-----END ${type}-----`;
        console.log(`Generated ${type} PEM:`, pem.substring(0, 100) + '...');
        return pem;
    }
    static _pemToArrayBuffer(pem) {
        console.log('Converting PEM to ArrayBuffer...');
        // Remove header/footer and all whitespace
        const b64 = pem.replace(/-----BEGIN [A-Z ]+-----/g, '').replace(/-----END [A-Z ]+-----/g, '').replace(/[\r\n\s]/g, '');
        console.log('Cleaned base64 length:', b64.length);
        console.log('Base64 sample:', b64.substring(0, 50) + '...');
        // Validate Base64 format
        if (!/^[A-Za-z0-9+/=]+$/.test(b64)) {
            console.error('Invalid characters found in base64:', b64.match(/[^A-Za-z0-9+/=]/g));
            throw new Error('Invalid PEM: contains non-Base64 characters');
        }
        try {
            // Decode base64 to binary
            const binary = atob(b64);
            console.log('Binary length:', binary.length);
            // Convert to ArrayBuffer
            const buffer = new ArrayBuffer(binary.length);
            const view = new Uint8Array(buffer);
            for(let i = 0; i < binary.length; i++){
                view[i] = binary.charCodeAt(i);
            }
            console.log('ArrayBuffer created successfully, size:', buffer.byteLength, 'bytes');
            return buffer;
        } catch (error) {
            console.error('Base64 decode failed:', error);
            throw new Error(`Failed to decode base64: ${error.message}`);
        }
    }
    static async _importPublicKey(publicKeyPem) {
        console.log('Key Import Starting...');
        console.log('PEM input length:', publicKeyPem?.length);
        console.log('PEM starts with:', publicKeyPem?.substring(0, 30));
        console.log('PEM ends with:', publicKeyPem?.substring(-30));
        try {
            // Step 1: Validate PEM format
            if (!publicKeyPem.includes('-----BEGIN PUBLIC KEY-----')) {
                throw new Error('Invalid PEM format - missing BEGIN header');
            }
            if (!publicKeyPem.includes('-----END PUBLIC KEY-----')) {
                throw new Error('Invalid PEM format - missing END header');
            }
            // Check if this looks like a client-generated key vs backend-generated
            console.log('🔑 Key source analysis:');
            console.log('🔑 Contains newlines:', publicKeyPem.includes('\n'));
            console.log('🔑 Line count:', publicKeyPem.split('\n').length);
            console.log('🔑 First few lines:', publicKeyPem.split('\n').slice(0, 3));
            // Step 2: Convert PEM to ArrayBuffer
            console.log('Step 2: Converting PEM to ArrayBuffer...');
            let buffer;
            try {
                buffer = this._pemToArrayBuffer(publicKeyPem);
                console.log('Buffer created, length:', buffer.byteLength);
                // Validate buffer looks like SPKI (should start with 0x30 for ASN.1 SEQUENCE)
                const firstBytes = new Uint8Array(buffer.slice(0, 10));
                console.log('First 10 bytes:', Array.from(firstBytes).map((b)=>'0x' + b.toString(16).padStart(2, '0')).join(' '));
                if (firstBytes[0] !== 0x30) {
                    console.warn('Buffer does not start with ASN.1 SEQUENCE (0x30)');
                }
            } catch (bufferError) {
                console.error('Buffer conversion failed:', bufferError);
                throw new Error(`PEM to buffer conversion failed: ${bufferError.message}`);
            }
            // Step 3: Import with Web Crypto API
            console.log('Step 3: Importing with Web Crypto API...');
            let key;
            try {
                key = await crypto.subtle.importKey('spki', buffer, {
                    name: 'RSA-OAEP',
                    hash: 'SHA-256'
                }, false, [
                    'encrypt'
                ]);
                console.log('Key imported successfully, type:', key.type, 'algorithm:', key.algorithm.name);
            } catch (importError) {
                console.error('Web Crypto import failed:', importError);
                throw new Error(`Web Crypto key import failed: ${importError.message}`);
            }
            return key;
        } catch (error) {
            console.error('Key Import FAILED:', {
                errorName: error.name,
                errorMessage: error.message,
                pemLength: publicKeyPem?.length,
                pemPreview: publicKeyPem?.substring(0, 100)
            });
            throw error;
        }
    }
    static async _importPrivateKey(privateKeyPem) {
        const buffer = this._pemToArrayBuffer(privateKeyPem);
        return await crypto.subtle.importKey('pkcs8', buffer, {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
        }, false, [
            'decrypt'
        ]);
    }
    // Fallback RSA key generation using JSEncrypt
    static _generateRSAKeyPairFallback() {
        try {
            console.log('Using JSEncrypt fallback for key generation');
            const jsencrypt = new __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$jsencrypt$2f$lib$2f$index$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$locals$3e$__["default"]({
                default_key_size: 2048
            });
            // Generate key pair
            const keyPair = jsencrypt.getKey();
            const publicKey = keyPair.getPublicKey();
            const privateKey = keyPair.getPrivateKey();
            console.log('JSEncrypt key pair generated successfully');
            return {
                publicKey: publicKey,
                privateKey: privateKey
            };
        } catch (error) {
            console.error('JSEncrypt fallback failed:', error);
            throw new Error(`Fallback key generation failed: ${error.message}`);
        }
    }
}
const __TURBOPACK__default__export__ = CryptoService;
}}),
"[project]/src/services/keyExchangeService.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
/**
 * KeyExchangeService - Handles RSA key exchange and management with enhanced validation and caching
 * All operations now use the actual GitHub username (lowercase) instead of numeric DB IDs.
 */ __turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
class KeyExchangeService {
    constructor(){
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
   */ _normalizeUsername(username) {
        if (!username || typeof username !== 'string') {
            throw new Error("GitHub username is required");
        }
        return username.trim().toLowerCase();
    }
    /**
   * Initialize keys and upload to GitHub
   */ async initializeKeys(githubUsername, githubToken) {
        githubUsername = this._normalizeUsername(githubUsername);
        console.log(' [KEY_INIT] Starting GitHub-based key initialization for user:', githubUsername);
        try {
            const keyStorageService = (await __turbopack_context__.r("[project]/src/services/keyStorageService.js [app-ssr] (ecmascript, async loader)")(__turbopack_context__.i)).default;
            // Try existing private key
            const existingPrivateKey = await keyStorageService.getPrivateKey(githubUsername);
            if (existingPrivateKey && await this.validateKeyPair(null, existingPrivateKey)) {
                console.log(' [KEY_INIT]  Using existing private key');
                this.myPrivateKey = existingPrivateKey;
                return true;
            }
            // Generate new RSA key pair
            console.log(' [KEY_INIT]  Generating new RSA key pair...');
            const CryptoService = (await __turbopack_context__.r("[project]/src/services/cryptoService.js [app-ssr] (ecmascript, async loader)")(__turbopack_context__.i)).default;
            const keyPair = await CryptoService.generateRSAKeyPair();
            this.myPrivateKey = keyPair.privateKey;
            this.myPublicKey = keyPair.publicKey;
            // Store private key locally under GitHub username
            await keyStorageService.storePrivateKey(githubUsername, this.myPrivateKey);
            console.log(' [KEY_INIT]  Private key stored locally');
            // Upload public key to GitHub
            if (githubToken) {
                const githubKeyService = (await __turbopack_context__.r("[project]/src/services/gitHubService.js [app-ssr] (ecmascript, async loader)")(__turbopack_context__.i)).default;
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
   */ async getUserPublicKey(githubUsername) {
        githubUsername = this._normalizeUsername(githubUsername);
        console.log(' [KEY_FETCH] Fetching public key from GitHub for:', githubUsername);
        try {
            const githubKeyService = (await __turbopack_context__.r("[project]/src/services/gitHubService.js [app-ssr] (ecmascript, async loader)")(__turbopack_context__.i)).default;
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
   */ async getRoomUserKeys(githubUsernames) {
        const keys = {};
        for (const username of githubUsernames){
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
   */ async refreshUserKey(githubUsername) {
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
   */ async validateKeyPair(publicKey, privateKey) {
        try {
            if (!privateKey) return false;
            if (!this._isValidPrivateKey(privateKey)) return false;
            if (publicKey && !this._isValidPublicKey(publicKey)) return false;
            const CryptoService = (await __turbopack_context__.r("[project]/src/services/cryptoService.js [app-ssr] (ecmascript, async loader)")(__turbopack_context__.i)).default;
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
   */ async rotateMyKeys(githubUsername, githubToken) {
        githubUsername = this._normalizeUsername(githubUsername);
        try {
            console.log(`Starting key rotation for user ${githubUsername}`);
            this.myPrivateKey = null;
            this.myPublicKey = null;
            const keyStorageService = (await __turbopack_context__.r("[project]/src/services/keyStorageService.js [app-ssr] (ecmascript, async loader)")(__turbopack_context__.i)).default;
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
            const keyStorageService = (await __turbopack_context__.r("[project]/src/services/keyStorageService.js [app-ssr] (ecmascript, async loader)")(__turbopack_context__.i)).default;
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
const __TURBOPACK__default__export__ = keyExchangeService;
}}),
"[project]/src/services/keyStorageService.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
/**
 * KeyStorageService - Secure browser key storage with validation and corruption detection
 * Handles storing/retrieving private keys in localStorage/IndexedDB with security measures
 */ __turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
class KeyStorageService {
    constructor(){
        this.storagePrefix = 'e2e_encryption_';
        this.privateKeyKey = 'private_key';
        this.publicKeyKey = 'public_key';
        this.keyVersionKey = 'key_version';
        this.keyTimestampKey = 'key_timestamp';
    }
    /**
   * Store private key securely in browser storage
   * @param {string} userId - User ID
   * @param {string} privateKey - RSA private key in PEM format
   * @returns {Promise<void>}
   */ async storePrivateKey(userId, privateKey) {
        try {
            if (!userId || !privateKey) {
                throw new Error('User ID and private key are required');
            }
            // Validate private key format
            if (!this._isValidPrivateKey(privateKey)) {
                throw new Error('Invalid private key format');
            }
            const keyData = {
                privateKey,
                timestamp: Date.now(),
                version: 1,
                userId
            };
            // Store in localStorage with user-specific key
            const storageKey = this._getStorageKey(userId, this.privateKeyKey);
            localStorage.setItem(storageKey, JSON.stringify(keyData));
            console.log(`Private key stored successfully for user ${userId}`);
        } catch (error) {
            console.error('Failed to store private key:', error);
            throw new Error(`Failed to store private key: ${error.message}`);
        }
    }
    /**
   * Retrieve private key from browser storage
   * @param {string} userId - User ID
   * @returns {Promise<string|null>} Private key or null if not found
   */ async getPrivateKey(userId) {
        try {
            if (!userId) {
                throw new Error('User ID is required');
            }
            const storageKey = this._getStorageKey(userId, this.privateKeyKey);
            const storedData = localStorage.getItem(storageKey);
            if (!storedData) {
                return null;
            }
            const keyData = JSON.parse(storedData);
            // Validate stored data structure
            if (!keyData.privateKey || !keyData.timestamp || !keyData.userId) {
                console.warn('Corrupted key data detected, clearing storage');
                await this.clearPrivateKey(userId);
                return null;
            }
            // Validate that the stored key belongs to the correct user
            if (keyData.userId !== userId) {
                console.warn('Key user ID mismatch, clearing storage');
                await this.clearPrivateKey(userId);
                return null;
            }
            // Validate private key format
            if (!this._isValidPrivateKey(keyData.privateKey)) {
                console.warn('Corrupted private key detected, clearing storage');
                await this.clearPrivateKey(userId);
                return null;
            }
            return keyData.privateKey;
        } catch (error) {
            console.error('Failed to retrieve private key:', error);
            // If there's an error parsing or accessing the key, clear it
            await this.clearPrivateKey(userId);
            return null;
        }
    }
    /**
   * Clear private key from browser storage
   * @param {string} userId - User ID
   * @returns {Promise<void>}
   */ async clearPrivateKey(userId) {
        try {
            if (!userId) {
                throw new Error('User ID is required');
            }
            const storageKey = this._getStorageKey(userId, this.privateKeyKey);
            localStorage.removeItem(storageKey);
            console.log(`Private key cleared for user ${userId}`);
        } catch (error) {
            console.error('Failed to clear private key:', error);
            throw new Error(`Failed to clear private key: ${error.message}`);
        }
    }
    /**
   * Validate stored key integrity and format
   * @param {string} userId - User ID
   * @returns {Promise<boolean>} True if key is valid, false otherwise
   */ async validateStoredKey(userId) {
        try {
            const privateKey = await this.getPrivateKey(userId);
            if (!privateKey) {
                return false;
            }
            // Additional validation: try to use the key for a test operation
            return await this._testKeyFunctionality(privateKey);
        } catch (error) {
            console.error('Key validation failed:', error);
            return false;
        }
    }
    /**
   * Clear all encryption keys from browser storage
   * @returns {Promise<void>}
   */ async clearAllKeys() {
        try {
            // Get all localStorage keys that match our prefix
            const keysToRemove = [];
            for(let i = 0; i < localStorage.length; i++){
                const key = localStorage.key(i);
                if (key && key.startsWith(this.storagePrefix)) {
                    keysToRemove.push(key);
                }
            }
            // Remove all matching keys
            keysToRemove.forEach((key)=>{
                localStorage.removeItem(key);
            });
            console.log(`Cleared ${keysToRemove.length} encryption keys from storage`);
        } catch (error) {
            console.error('Failed to clear all keys:', error);
            throw new Error(`Failed to clear all keys: ${error.message}`);
        }
    }
    /**
   * Get storage information and statistics
   * @returns {Object} Storage information
   */ getStorageInfo() {
        try {
            const info = {
                storageType: 'localStorage',
                totalKeys: 0,
                encryptionKeys: 0,
                storageUsed: 0,
                isAvailable: this._isStorageAvailable()
            };
            // Count keys and calculate storage usage
            for(let i = 0; i < localStorage.length; i++){
                const key = localStorage.key(i);
                if (key) {
                    info.totalKeys++;
                    const value = localStorage.getItem(key);
                    info.storageUsed += key.length + (value ? value.length : 0);
                    if (key.startsWith(this.storagePrefix)) {
                        info.encryptionKeys++;
                    }
                }
            }
            return info;
        } catch (error) {
            console.error('Failed to get storage info:', error);
            return {
                storageType: 'localStorage',
                totalKeys: 0,
                encryptionKeys: 0,
                storageUsed: 0,
                isAvailable: false,
                error: error.message
            };
        }
    }
    /**
   * Store public key for caching purposes
   * @param {string} userId - User ID
   * @param {string} publicKey - RSA public key in PEM format
   * @returns {Promise<void>}
   */ async storePublicKey(userId, publicKey) {
        try {
            if (!userId || !publicKey) {
                throw new Error('User ID and public key are required');
            }
            const keyData = {
                publicKey,
                timestamp: Date.now(),
                userId
            };
            const storageKey = this._getStorageKey(userId, this.publicKeyKey);
            localStorage.setItem(storageKey, JSON.stringify(keyData));
        } catch (error) {
            console.error('Failed to store public key:', error);
        // Don't throw error for public key storage failures
        }
    }
    /**
   * Retrieve cached public key
   * @param {string} userId - User ID
   * @returns {Promise<string|null>} Public key or null if not found
   */ async getPublicKey(userId) {
        try {
            if (!userId) {
                return null;
            }
            const storageKey = this._getStorageKey(userId, this.publicKeyKey);
            const storedData = localStorage.getItem(storageKey);
            if (!storedData) {
                return null;
            }
            const keyData = JSON.parse(storedData);
            return keyData.publicKey || null;
        } catch (error) {
            console.error('Failed to retrieve public key:', error);
            return null;
        }
    }
    // Private helper methods
    /**
   * Generate storage key with prefix and user ID
   * @param {string} userId - User ID
   * @param {string} keyType - Type of key (private_key, public_key, etc.)
   * @returns {string} Storage key
   */ _getStorageKey(userId, keyType) {
        return `${this.storagePrefix}${userId}_${keyType}`;
    }
    /**
   * Validate private key format (basic PEM format check)
   * @param {string} privateKey - Private key to validate
   * @returns {boolean} True if valid format
   */ _isValidPrivateKey(privateKey) {
        if (!privateKey || typeof privateKey !== 'string') {
            return false;
        }
        // Check for both PKCS#1 and PKCS#8 private key PEM formats
        const pkcs1Regex = /^-----BEGIN RSA PRIVATE KEY-----[\s\S]*-----END RSA PRIVATE KEY-----$/;
        const pkcs8Regex = /^-----BEGIN PRIVATE KEY-----[\s\S]*-----END PRIVATE KEY-----$/;
        return pkcs1Regex.test(privateKey.trim()) || pkcs8Regex.test(privateKey.trim());
    }
    /**
   * Test key functionality by performing a simple operation
   * @param {string} privateKey - Private key to test
   * @returns {Promise<boolean>} True if key works
   */ async _testKeyFunctionality(privateKey) {
        try {
            // Import CryptoService dynamically to avoid circular dependencies
            const CryptoService = (await __turbopack_context__.r("[project]/src/services/cryptoService.js [app-ssr] (ecmascript, async loader)")(__turbopack_context__.i)).default;
            // Try to generate a signature with the private key
            const testData = 'test_key_validation';
            const signature = await CryptoService.signWithRSA(testData, privateKey);
            // If we got a signature, the key is functional
            return !!signature;
        } catch (error) {
            console.warn('Key functionality test failed:', error);
            return false;
        }
    }
    /**
   * Check if localStorage is available
   * @returns {boolean} True if storage is available
   */ _isStorageAvailable() {
        try {
            const test = '__storage_test__';
            localStorage.setItem(test, test);
            localStorage.removeItem(test);
            return true;
        } catch (error) {
            return false;
        }
    }
}
// Export singleton instance
const keyStorageService = new KeyStorageService();
const __TURBOPACK__default__export__ = keyStorageService;
}}),
"[project]/src/services/encryptionService.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
/**
 * EncryptionService - High-level message encryption orchestration service
 * Orchestrates complete encrypt/decrypt message flow with error handling and graceful degradation
 */ __turbopack_context__.s({
    "EncryptionErrorTypes": (()=>EncryptionErrorTypes),
    "EncryptionStatus": (()=>EncryptionStatus),
    "default": (()=>__TURBOPACK__default__export__)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/cryptoService.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/keyExchangeService.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyStorageService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/keyStorageService.js [app-ssr] (ecmascript)");
;
;
;
const EncryptionErrorTypes = {
    KEY_GENERATION_FAILED: 'key_generation_failed',
    ENCRYPTION_FAILED: 'encryption_failed',
    DECRYPTION_FAILED: 'decryption_failed',
    KEY_EXCHANGE_FAILED: 'key_exchange_failed',
    SIGNATURE_VERIFICATION_FAILED: 'signature_verification_failed',
    STORAGE_FAILED: 'storage_failed',
    INITIALIZATION_FAILED: 'initialization_failed'
};
const EncryptionStatus = {
    AVAILABLE: 'available',
    UNAVAILABLE: 'unavailable',
    INITIALIZING: 'initializing',
    ERROR: 'error'
};
class EncryptionService {
    constructor(){
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
   */ async initialize(userId, token) {
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
   */ async encryptMessage(message, recipientGithubUsername) {
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
            const aesKey = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].generateAESKey();
            console.log('ENCRYPTION: Generated AES key');
            // Encrypt message with AES
            const encryptedMessage = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].encryptWithAES(message, aesKey);
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
   */ async decryptMessage(encryptedData, senderUserId) {
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
            const myPublicKey = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getMyPublicKey();
            const myKeyVersion = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getMyKeyVersion();
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
            const decryptedMessage = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].decryptWithAES(encryptedData.content, encryptedData.iv, aesKey);
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
   */ async decryptMessageWithoutSignature(encryptedData) {
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
            const aesKey = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].decryptWithRSA(encryptedData.encrypted_aes_key, myPrivateKey);
            // Decrypt message content with AES key
            const decryptedMessage = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].decryptWithAES(encryptedData.content, encryptedData.iv, aesKey);
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
   */ isEncryptionAvailable() {
        return this.isInitialized && this.currentUserId && this.currentToken && __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getMyPrivateKey() !== null;
    }
    /**
   * Get current encryption status
   * @returns {Object} Encryption status information
   */ getEncryptionStatus() {
        const hasPrivateKey = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getMyPrivateKey() !== null;
        const hasPublicKey = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getMyPublicKey() !== null;
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
   */ handleEncryptionError(error) {
        return this._createErrorInfo(EncryptionErrorTypes.ENCRYPTION_FAILED, error);
    }
    /**
   * Clear encryption state and keys (for logout)
   * @returns {Promise<void>}
   */ async clearEncryption() {
        try {
            if (this.currentUserId) {
                await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyStorageService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].clearPrivateKey(this.currentUserId);
            }
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].clearCache();
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
   */ async refreshKeys() {
        try {
            if (!this.currentUserId || !this.currentToken) {
                throw new Error('User not initialized');
            }
            // Clear existing keys
            await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyStorageService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].clearPrivateKey(this.currentUserId);
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].clearCache();
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
   */ async _performInitialization(userId, token) {
        console.log('INIT: Starting encryption service initialization');
        console.log('INIT: User ID:', userId);
        try {
            this.currentUserId = userId;
            this.currentToken = token;
            // Try to load existing private key from storage
            console.log('INIT: Checking for existing private key...');
            let privateKey = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyStorageService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getPrivateKey(userId);
            let publicKey = null;
            if (privateKey) {
                console.log('INIT: Found existing private key, validating...');
                const isValid = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyStorageService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].validateStoredKey(userId);
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
                const keyPair = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].generateRSAKeyPair();
                privateKey = keyPair.privateKey;
                publicKey = keyPair.publicKey;
                console.log('INIT: RSA key pair generated successfully');
                // Store private key securely
                console.log('INIT: Storing private key securely...');
                await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyStorageService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].storePrivateKey(userId, privateKey);
                console.log('INIT: Private key stored securely');
                this.keyGenerationTime = new Date();
            }
            // Initialize key exchange service
            console.log('INIT: Initializing key exchange service...');
            await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].initializeKeys(userId, token);
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
   */ async _getRecipientPublicKey(recipientGithubUsername) {
        console.log('KEY_EXCHANGE: FRESH fetch of public key for recipient:', recipientGithubUsername);
        try {
            // Directly fetch PEM from GitHub via keyExchangeService
            const pemKey = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getUserPublicKey(recipientGithubUsername);
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
   */ async _getMyPrivateKey() {
        const privateKey = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getMyPrivateKey();
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
   */ async _generateRoomKey(userId1, userId2) {
        // Create deterministic key based on both user IDs
        const sortedIds = [
            userId1,
            userId2
        ].sort();
        const keyString = `room_key_${sortedIds[0]}_${sortedIds[1]}_secret`;
        console.log('ROOM_KEY: Generating key for users:', userId1, 'and', userId2);
        console.log('ROOM_KEY: Sorted IDs:', sortedIds);
        console.log('ROOM_KEY: Key string:', keyString);
        // Generate SHA-256 hash and convert to hex
        const encoder = new TextEncoder();
        const data = encoder.encode(keyString);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = new Uint8Array(hashBuffer);
        const roomKey = Array.from(hashArray).map((b)=>b.toString(16).padStart(2, '0')).join('');
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
   */ async _verifyMessageSignature(message, signature, senderUserId) {
        console.log('[SIGNATURE] Verifying message signature from sender:', senderUserId);
        try {
            console.log('[SIGNATURE] Getting sender public key for verification...');
            const senderPublicKey = await this._getRecipientPublicKey(senderUserId);
            console.log('[SIGNATURE]  Sender public key obtained');
            console.log('[SIGNATURE] Verifying RSA signature...');
            const isValid = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].verifyRSASignature(message, signature, senderPublicKey);
            if (!isValid) {
                console.warn('[SIGNATURE]  Signature verification failed for message from', senderUserId);
                this.lastError = this._createErrorInfo(EncryptionErrorTypes.SIGNATURE_VERIFICATION_FAILED, new Error('Message signature verification failed'));
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
   */ _createErrorInfo(type, error) {
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
   */ _getUserFriendlyErrorMessage(type, error) {
        switch(type){
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
   */ async _encryptWithPublicKey(data, publicKeyPem) {
        console.log('RSA_ENCRYPT: Using REAL Web Crypto API RSA encryption');
        try {
            // Convert PEM to ArrayBuffer
            const publicKeyBuffer = this._pemToArrayBuffer(publicKeyPem);
            // Import the public key
            const publicKey = await crypto.subtle.importKey('spki', publicKeyBuffer, {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            }, false, [
                'encrypt'
            ]);
            // Encrypt the data
            const dataBuffer = new TextEncoder().encode(data);
            const encryptedBuffer = await crypto.subtle.encrypt({
                name: 'RSA-OAEP'
            }, publicKey, dataBuffer);
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
   */ async _decryptWithPrivateKey(encryptedData, privateKeyPem) {
        console.log('RSA_DECRYPT: Using REAL Web Crypto API RSA decryption');
        try {
            // Convert PEM to ArrayBuffer
            const privateKeyBuffer = this._pemToArrayBuffer(privateKeyPem);
            // Import the private key
            const privateKey = await crypto.subtle.importKey('pkcs8', privateKeyBuffer, {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            }, false, [
                'decrypt'
            ]);
            // Convert base64 to ArrayBuffer
            const encryptedArray = new Uint8Array(atob(encryptedData).split('').map((char)=>char.charCodeAt(0)));
            // Decrypt the data
            const decryptedBuffer = await crypto.subtle.decrypt({
                name: 'RSA-OAEP'
            }, privateKey, encryptedArray);
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
   */ _pemToArrayBuffer(pem) {
        const base64 = pem.replace(/-----BEGIN [A-Z ]+-----/g, '').replace(/-----END [A-Z ]+-----/g, '').replace(/[\r\n\s]/g, '');
        const binaryString = atob(base64);
        const buffer = new ArrayBuffer(binaryString.length);
        const view = new Uint8Array(buffer);
        for(let i = 0; i < binaryString.length; i++){
            view[i] = binaryString.charCodeAt(i);
        }
        return buffer;
    }
    /**
   * Sign data with RSA private key
   */ async _signWithPrivateKey(data, privateKeyPem) {
        return await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].signWithRSA(data, privateKeyPem);
    }
    /**
   * Verify signature with RSA public key
   */ async _verifyWithPublicKey(data, signature, publicKeyPem) {
        return await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].verifyRSASignature(data, signature, publicKeyPem);
    }
}
// Export singleton instance
const encryptionService = new EncryptionService();
const __TURBOPACK__default__export__ = encryptionService;
}}),
"[project]/src/services/userPreferencesService.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
/**
 * UserPreferencesService - Manages user preferences for encryption and other settings
 * Handles storing/retrieving user preferences in localStorage with validation
 */ __turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
class UserPreferencesService {
    constructor(){
        this.storageKey = 'user_preferences';
        this.defaultPreferences = {
            encryption: {
                clearKeysOnLogout: false,
                keyPersistenceAcrossSessions: true,
                autoInitializeKeys: true
            },
            ui: {
                showEncryptionIndicators: true,
                showKeyInitializationProgress: true
            }
        };
    }
    /**
   * Get all user preferences
   * @returns {Object} User preferences object
   */ getPreferences() {
        try {
            const stored = localStorage.getItem(this.storageKey);
            if (stored) {
                const parsed = JSON.parse(stored);
                // Merge with defaults to ensure all properties exist
                return this._mergeWithDefaults(parsed);
            }
        } catch (error) {
            console.error('Failed to load user preferences:', error);
        }
        return {
            ...this.defaultPreferences
        };
    }
    /**
   * Update user preferences
   * @param {Object} preferences - Preferences to update
   */ updatePreferences(preferences) {
        try {
            const current = this.getPreferences();
            const updated = this._deepMerge(current, preferences);
            localStorage.setItem(this.storageKey, JSON.stringify(updated));
            return updated;
        } catch (error) {
            console.error('Failed to save user preferences:', error);
            throw error;
        }
    }
    /**
   * Get encryption-specific preferences
   * @returns {Object} Encryption preferences
   */ getEncryptionPreferences() {
        return this.getPreferences().encryption;
    }
    /**
   * Update encryption preferences
   * @param {Object} encryptionPrefs - Encryption preferences to update
   */ updateEncryptionPreferences(encryptionPrefs) {
        return this.updatePreferences({
            encryption: encryptionPrefs
        });
    }
    /**
   * Check if keys should be cleared on logout
   * @returns {boolean}
   */ shouldClearKeysOnLogout() {
        return this.getEncryptionPreferences().clearKeysOnLogout;
    }
    /**
   * Check if keys should persist across sessions
   * @returns {boolean}
   */ shouldPersistKeysAcrossSessions() {
        return this.getEncryptionPreferences().keyPersistenceAcrossSessions;
    }
    /**
   * Check if keys should be auto-initialized
   * @returns {boolean}
   */ shouldAutoInitializeKeys() {
        return this.getEncryptionPreferences().autoInitializeKeys;
    }
    /**
   * Reset preferences to defaults
   */ resetToDefaults() {
        try {
            localStorage.removeItem(this.storageKey);
        } catch (error) {
            console.error('Failed to reset preferences:', error);
        }
    }
    /**
   * Clear all preferences
   */ clearPreferences() {
        this.resetToDefaults();
    }
    /**
   * Merge preferences with defaults to ensure all properties exist
   * @private
   */ _mergeWithDefaults(preferences) {
        return this._deepMerge(this.defaultPreferences, preferences);
    }
    /**
   * Deep merge two objects
   * @private
   */ _deepMerge(target, source) {
        const result = {
            ...target
        };
        for(const key in source){
            if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                result[key] = this._deepMerge(target[key] || {}, source[key]);
            } else {
                result[key] = source[key];
            }
        }
        return result;
    }
}
// Export singleton instance
const userPreferencesService = new UserPreferencesService();
const __TURBOPACK__default__export__ = userPreferencesService;
}}),
"[project]/src/context/AuthContext.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "AuthProvider": (()=>AuthProvider),
    "useAuth": (()=>useAuth)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/encryptionService.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$userPreferencesService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/userPreferencesService.js [app-ssr] (ecmascript)");
'use client';
;
;
;
;
const AuthContext = /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["createContext"])({});
const useAuth = ()=>{
    return (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useContext"])(AuthContext);
};
const AuthProvider = ({ children })=>{
    const [currentUser, setCurrentUser] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(null);
    const [loading, setLoading] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(true);
    const [error, setError] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(null);
    const [keyInitialization, setKeyInitialization] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])({
        isInitializing: false,
        progress: 0,
        status: null,
        error: null
    });
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        // Check if user is already authenticated
        checkAuthStatus();
    }, []);
    const checkAuthStatus = async ()=>{
        try {
            const backendUrl = ("TURBOPACK compile-time value", "http://localhost:5000") || 'http://localhost:5000';
            const response = await fetch(`${backendUrl}/api/auth/me`, {
                method: 'GET',
                credentials: 'include'
            });
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success') {
                    // Create user object compatible with the app
                    const user = {
                        uid: data.data.id.toString(),
                        email: data.data.email,
                        displayName: data.data.display_name,
                        username: data.data.username,
                        githubUsername: data.data.github_username,
                        photoURL: data.data.profile_picture,
                        accessToken: 'local-auth-token'
                    };
                    setCurrentUser(user);
                    setError(null);
                    // Initialize encryption keys for existing session
                    await initializeEncryptionKeys(user);
                } else {
                    setCurrentUser(null);
                }
            } else {
                setCurrentUser(null);
            }
        } catch (err) {
            console.error('Auth check error:', err);
            setCurrentUser(null);
        } finally{
            setLoading(false);
        }
    };
    const initializeEncryptionKeys = async (user)=>{
        try {
            setKeyInitialization({
                isInitializing: true,
                progress: 0,
                status: 'Initializing encryption keys...',
                error: null
            });
            // Progress: Starting key initialization
            setKeyInitialization((prev)=>({
                    ...prev,
                    progress: 20,
                    status: 'Checking existing keys...'
                }));
            // Initialize encryption service with user credentials
            const success = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].initialize(user.uid, user.accessToken);
            if (success) {
                setKeyInitialization((prev)=>({
                        ...prev,
                        progress: 100,
                        status: 'Encryption keys ready',
                        isInitializing: false
                    }));
                // Clear status after a short delay
                setTimeout(()=>{
                    setKeyInitialization({
                        isInitializing: false,
                        progress: 0,
                        status: null,
                        error: null
                    });
                }, 2000);
            } else {
                throw new Error('Failed to initialize encryption keys');
            }
        } catch (error) {
            console.error('Key initialization error:', error);
            setKeyInitialization({
                isInitializing: false,
                progress: 0,
                status: null,
                error: error.message || 'Failed to initialize encryption keys'
            });
        }
    };
    const logout = async (options = {})=>{
        try {
            setLoading(true);
            // Check user preferences for key cleanup
            const shouldClearKeys = options.clearKeys !== undefined ? options.clearKeys : __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$userPreferencesService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].shouldClearKeysOnLogout();
            // Clear encryption keys based on user preference
            if (currentUser && shouldClearKeys) {
                await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].clearKeys();
                console.log('Encryption keys cleared on logout');
            } else if (currentUser) {
                console.log('Encryption keys preserved on logout (user preference)');
            }
            // Clear backend session
            const backendUrl = ("TURBOPACK compile-time value", "http://localhost:5000") || 'http://localhost:5000';
            await fetch(`${backendUrl}/api/auth/logout`, {
                method: 'POST',
                credentials: 'include'
            });
            setCurrentUser(null);
            setError(null);
            setKeyInitialization({
                isInitializing: false,
                progress: 0,
                status: null,
                error: null
            });
        } catch (err) {
            console.error('Logout error:', err);
            setError(err.message);
        } finally{
            setLoading(false);
        }
    };
    const clearError = ()=>{
        setError(null);
    };
    const refreshUser = async ()=>{
        setLoading(true);
        await checkAuthStatus();
    };
    const login = async (user)=>{
        setCurrentUser(user);
        setError(null);
        // Initialize encryption keys after successful login
        await initializeEncryptionKeys(user);
    };
    const updateUserPreferences = (preferences)=>{
        return __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$userPreferencesService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].updatePreferences(preferences);
    };
    const getUserPreferences = ()=>{
        return __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$userPreferencesService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getPreferences();
    };
    const clearKeysManually = async ()=>{
        if (currentUser) {
            await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].clearKeys();
            console.log('Encryption keys manually cleared');
        }
    };
    const value = {
        currentUser,
        login,
        logout,
        loading,
        error,
        clearError,
        refreshUser,
        keyInitialization,
        updateUserPreferences,
        getUserPreferences,
        clearKeysManually
    };
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(AuthContext.Provider, {
        value: value,
        children: children
    }, void 0, false, {
        fileName: "[project]/src/context/AuthContext.js",
        lineNumber: 205,
        columnNumber: 5
    }, this);
};
}}),
"[project]/src/components/ErrorBoundary.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/triangle-alert.js [app-ssr] (ecmascript) <export default as AlertTriangle>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$refresh$2d$cw$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__RefreshCw$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/refresh-cw.js [app-ssr] (ecmascript) <export default as RefreshCw>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$house$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Home$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/house.js [app-ssr] (ecmascript) <export default as Home>");
"use client";
;
;
;
class ErrorBoundary extends __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].Component {
    constructor(props){
        super(props);
        this.state = {
            hasError: false,
            error: null,
            errorInfo: null
        };
    }
    static getDerivedStateFromError(error) {
        return {
            hasError: true
        };
    }
    componentDidCatch(error, errorInfo) {
        this.setState({
            error: error,
            errorInfo: errorInfo
        });
        // Log error to console in development
        if ("TURBOPACK compile-time truthy", 1) {
            console.error('Error caught by boundary:', error, errorInfo);
        }
        // In production, you would send this to an error reporting service
        // Example: Sentry, LogRocket, etc.
        if (("TURBOPACK compile-time value", "development") === 'production') {
        // logErrorToService(error, errorInfo);
        }
    }
    handleReload = ()=>{
        window.location.reload();
    };
    handleGoHome = ()=>{
        window.location.href = '/';
    };
    render() {
        if (this.state.hasError) {
            return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "min-h-screen flex items-center justify-center bg-gray-50 px-4",
                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "max-w-md w-full text-center",
                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "bg-white rounded-lg shadow-lg p-8",
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4",
                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                                    className: "w-8 h-8 text-red-600"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ErrorBoundary.js",
                                    lineNumber: 48,
                                    columnNumber: 17
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/components/ErrorBoundary.js",
                                lineNumber: 47,
                                columnNumber: 15
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h1", {
                                className: "text-xl font-semibold text-gray-900 mb-2",
                                children: "Something went wrong"
                            }, void 0, false, {
                                fileName: "[project]/src/components/ErrorBoundary.js",
                                lineNumber: 51,
                                columnNumber: 15
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                className: "text-gray-600 mb-6",
                                children: "We're sorry, but something unexpected happened. Please try refreshing the page or go back to the home page."
                            }, void 0, false, {
                                fileName: "[project]/src/components/ErrorBoundary.js",
                                lineNumber: 55,
                                columnNumber: 15
                            }, this),
                            ("TURBOPACK compile-time value", "development") === 'development' && this.state.error && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "bg-red-50 border border-red-200 rounded-md p-4 mb-6 text-left",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                                        className: "text-sm font-medium text-red-800 mb-2",
                                        children: "Error Details:"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ErrorBoundary.js",
                                        lineNumber: 61,
                                        columnNumber: 19
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("pre", {
                                        className: "text-xs text-red-700 overflow-auto max-h-32",
                                        children: [
                                            this.state.error.toString(),
                                            this.state.errorInfo.componentStack
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/ErrorBoundary.js",
                                        lineNumber: 62,
                                        columnNumber: 19
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/ErrorBoundary.js",
                                lineNumber: 60,
                                columnNumber: 17
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "flex flex-col sm:flex-row gap-3",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                        onClick: this.handleReload,
                                        className: "flex-1 flex items-center justify-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$refresh$2d$cw$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__RefreshCw$3e$__["RefreshCw"], {
                                                className: "w-4 h-4 mr-2"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ErrorBoundary.js",
                                                lineNumber: 74,
                                                columnNumber: 19
                                            }, this),
                                            "Refresh Page"
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/ErrorBoundary.js",
                                        lineNumber: 70,
                                        columnNumber: 17
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                        onClick: this.handleGoHome,
                                        className: "flex-1 flex items-center justify-center px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$house$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Home$3e$__["Home"], {
                                                className: "w-4 h-4 mr-2"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ErrorBoundary.js",
                                                lineNumber: 82,
                                                columnNumber: 19
                                            }, this),
                                            "Go Home"
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/ErrorBoundary.js",
                                        lineNumber: 78,
                                        columnNumber: 17
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/ErrorBoundary.js",
                                lineNumber: 69,
                                columnNumber: 15
                            }, this)
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/ErrorBoundary.js",
                        lineNumber: 46,
                        columnNumber: 13
                    }, this)
                }, void 0, false, {
                    fileName: "[project]/src/components/ErrorBoundary.js",
                    lineNumber: 45,
                    columnNumber: 11
                }, this)
            }, void 0, false, {
                fileName: "[project]/src/components/ErrorBoundary.js",
                lineNumber: 44,
                columnNumber: 9
            }, this);
        }
        return this.props.children;
    }
}
const __TURBOPACK__default__export__ = ErrorBoundary;
}}),
"[externals]/next/dist/server/app-render/work-async-storage.external.js [external] (next/dist/server/app-render/work-async-storage.external.js, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/server/app-render/work-async-storage.external.js", () => require("next/dist/server/app-render/work-async-storage.external.js"));

module.exports = mod;
}}),
"[externals]/next/dist/server/app-render/action-async-storage.external.js [external] (next/dist/server/app-render/action-async-storage.external.js, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/server/app-render/action-async-storage.external.js", () => require("next/dist/server/app-render/action-async-storage.external.js"));

module.exports = mod;
}}),
"[externals]/next/dist/server/app-render/work-unit-async-storage.external.js [external] (next/dist/server/app-render/work-unit-async-storage.external.js, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/server/app-render/work-unit-async-storage.external.js", () => require("next/dist/server/app-render/work-unit-async-storage.external.js"));

module.exports = mod;
}}),
"[externals]/next/dist/server/app-render/after-task-async-storage.external.js [external] (next/dist/server/app-render/after-task-async-storage.external.js, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("next/dist/server/app-render/after-task-async-storage.external.js", () => require("next/dist/server/app-render/after-task-async-storage.external.js"));

module.exports = mod;
}}),

};

//# sourceMappingURL=%5Broot-of-the-server%5D__25ffc62b._.js.map