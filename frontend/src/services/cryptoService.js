/**
 * CryptoService - Web Crypto API and JSEncrypt wrapper for RSA and AES operations
 * Implements end-to-end encryption functionality for the chat application
 * Uses RSA-2048 for key exchange and AES-256-GCM for message encryption
 */

import CryptoJS from 'crypto-js';
import JSEncrypt from 'jsencrypt';

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
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: 'RSA-OAEP',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256'
                },
                true,
                ['encrypt', 'decrypt']
            );
            
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
     */
    static async exportPublicKey(publicKey) {
        try {
            return publicKey; // Just return the PEM string directly - simpler!
        } catch (error) {
            throw new Error(`Failed to export public key: ${error.message}`);
        }
    }

    /**
     * Import RSA public key
     */
    static async importPublicKey(publicKeyPem) {
        try {
            return publicKeyPem; // Just return the PEM string directly - simpler!
        } catch (error) {
            throw new Error(`Failed to import public key: ${error.message}`);
        }
    }

    /**
     * Encrypt data using RSA public key with Web Crypto API
     */
    static async encryptWithRSA(data, publicKeyPem) {
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
                encryptedBuffer = await crypto.subtle.encrypt(
                    {
                        name: 'RSA-OAEP'
                    },
                    publicKey,
                    dataBuffer
                );
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
     */
    static async decryptWithRSA(encryptedData, privateKeyPem) {
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
                for (let i = 0; i < binaryString.length; i++) {
                    encryptedArray[i] = binaryString.charCodeAt(i);
                }
                console.log('Encrypted data converted to array, length:', encryptedArray.length);
            } catch (b64Error) {
                console.error('Base64 decode failed:', b64Error);
                throw new Error(`Invalid base64 data: ${b64Error.message}`);
            }
            
            // Decrypt with RSA-OAEP
            console.log('Attempting RSA-OAEP decryption...');
            const decryptedBuffer = await crypto.subtle.decrypt(
                {
                    name: 'RSA-OAEP'
                },
                privateKey,
                encryptedArray
            );
            
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
     */
    static async signWithRSA(data, privateKeyPem) {
        try {
            console.log('RSA Signing with Web Crypto API');
            
            // Import the private key for signing
            const buffer = this._pemToArrayBuffer(privateKeyPem);
            const privateKey = await crypto.subtle.importKey(
                'pkcs8',
                buffer,
                {
                    name: 'RSA-PSS',
                    hash: 'SHA-256'
                },
                false,
                ['sign']
            );
            
            // Sign the data
            const dataBuffer = new TextEncoder().encode(data);
            const signatureBuffer = await crypto.subtle.sign(
                {
                    name: 'RSA-PSS',
                    saltLength: 32
                },
                privateKey,
                dataBuffer
            );
            
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
     */
    static async verifyRSASignature(data, signature, publicKeyPem) {
        try {
            console.log('RSA Signature verification with Web Crypto API');
            
            // Import the public key for verification
            const buffer = this._pemToArrayBuffer(publicKeyPem);
            const publicKey = await crypto.subtle.importKey(
                'spki',
                buffer,
                {
                    name: 'RSA-PSS',
                    hash: 'SHA-256'
                },
                false,
                ['verify']
            );
            
            // Convert signature from base64
            const signatureArray = new Uint8Array(
                atob(signature).split('').map(char => char.charCodeAt(0))
            );
            
            // Verify the signature
            const dataBuffer = new TextEncoder().encode(data);
            const isValid = await crypto.subtle.verify(
                {
                    name: 'RSA-PSS',
                    saltLength: 32
                },
                publicKey,
                signatureArray,
                dataBuffer
            );
            
            console.log('RSA signature verification result:', isValid);
            return isValid;
        } catch (error) {
            console.error('RSA Signature verification error:', error);
            return false;
        }
    }

    /**
     * Generate AES key for message encryption using Web Crypto API
     */
    static async generateAESKey() {
        try {
            // Generate 256-bit AES key using Web Crypto API
            const key = await crypto.subtle.generateKey(
                {
                    name: 'AES-GCM',
                    length: 256
                },
                true, // extractable
                ['encrypt', 'decrypt']
            );

            // Export key as raw bytes and convert to hex
            const keyBuffer = await crypto.subtle.exportKey('raw', key);
            const keyArray = new Uint8Array(keyBuffer);
            return Array.from(keyArray).map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (error) {
            throw new Error(`Failed to generate AES key: ${error.message}`);
        }
    }

    /**
     * Encrypt message using AES-256-GCM with Web Crypto API
     */
    static async encryptWithAES(message, aesKeyHex) {
        try {
            // Generate random IV for each message (96-bit IV for GCM)
            const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM

            // Convert hex key to Uint8Array
            const keyBytes = new Uint8Array(aesKeyHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));

            // Import the key
            const key = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'AES-GCM' },
                false,
                ['encrypt']
            );

            // Encrypt the message
            const messageBytes = new TextEncoder().encode(message);
            const encryptedBuffer = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                messageBytes
            );

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
     */
    static async decryptWithAES(encryptedData, ivB64, aesKeyHex) {
        try {
            // Convert base64 to Uint8Array
            const encryptedBytes = new Uint8Array(
                atob(encryptedData).split('').map(char => char.charCodeAt(0))
            );
            const iv = new Uint8Array(
                atob(ivB64).split('').map(char => char.charCodeAt(0))
            );

            // Convert hex key to Uint8Array
            const keyBytes = new Uint8Array(aesKeyHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));

            // Import the key
            const key = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );

            // Decrypt the message
            const decryptedBuffer = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                encryptedBytes
            );

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
     */
    static async exportAESKey(aesKeyHex) {
        try {
            return aesKeyHex; // Just return the hex string directly - simpler!
        } catch (error) {
            throw new Error(`Failed to export AES key: ${error.message}`);
        }
    }

    /**
     * Import AES key (accepts hex format directly for simplicity)
     */
    static async importAESKey(aesKeyHex) {
        try {
            return aesKeyHex; // Just return the hex string directly - simpler!
        } catch (error) {
            throw new Error(`Failed to import AES key: ${error.message}`);
        }
    }

    /**
     * Export RSA private key
     */
    static async exportPrivateKey(privateKey) {
        try {
            return privateKey; // Just return the PEM string directly - simpler!
        } catch (error) {
            throw new Error(`Failed to export private key: ${error.message}`);
        }
    }

    /**
     * Import RSA private key 
     */
    static async importPrivateKey(privateKeyPem) {
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
        const b64 = pem
            .replace(/-----BEGIN [A-Z ]+-----/g, '')
            .replace(/-----END [A-Z ]+-----/g, '')
            .replace(/[\r\n\s]/g, '');
        
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
            for (let i = 0; i < binary.length; i++) {
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
                console.log('First 10 bytes:', Array.from(firstBytes).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' '));
                
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
                key = await crypto.subtle.importKey(
                    'spki',
                    buffer,
                    {
                        name: 'RSA-OAEP',
                        hash: 'SHA-256'
                    },
                    false,
                    ['encrypt']
                );
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
        return await crypto.subtle.importKey(
            'pkcs8',
            buffer,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            false,
            ['decrypt']
        );
    }
    
    // Fallback RSA key generation using JSEncrypt
    static _generateRSAKeyPairFallback() {
        try {
            console.log('Using JSEncrypt fallback for key generation');
            const jsencrypt = new JSEncrypt({ default_key_size: 2048 });
            
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

export default CryptoService;