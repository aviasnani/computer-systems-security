// Manual key upload utility for testing
import githubKeyService from '../services/gitHubService';
import CryptoService from '../services/cryptoService';

export async function manualKeyUpload() {
  try {
    const githubToken = localStorage.getItem('github_token');
    const githubUsername = localStorage.getItem('github_username');
    
    if (!githubToken) {
      throw new Error('No GitHub token found. Please login first.');
    }
    
    console.log('🔑 [MANUAL] Starting manual key upload...');
    console.log('🔑 [MANUAL] GitHub username:', githubUsername);
    console.log('🔑 [MANUAL] GitHub token available:', !!githubToken);
    
    // Generate new key pair
    const keyPair = await CryptoService.generateRSAKeyPair();
    console.log('🔑 [MANUAL] Generated new RSA key pair');
    
    // Store private key
    localStorage.setItem('private_key', keyPair.privateKey);
    console.log('🔑 [MANUAL] Stored private key locally');
    
    // Upload public key to GitHub
    const uploadResult = await githubKeyService.uploadPublicKey(keyPair.publicKey, githubToken, 'Manual SecureChat Key');
    console.log('🔑 [MANUAL] ✅ Key uploaded successfully:', uploadResult.id);
    
    // Verify upload
    const keys = await githubKeyService.fetchUserPublicKeys(githubUsername);
    console.log('🔑 [MANUAL] ✅ Verification: Found', keys.length, 'SSH keys on GitHub');
    
    return { success: true, keyId: uploadResult.id, totalKeys: keys.length };
    
  } catch (error) {
    console.error('🔑 [MANUAL] ❌ Manual key upload failed:', error);
    throw error;
  }
}

// Add to window for easy testing
if (typeof window !== 'undefined') {
  window.manualKeyUpload = manualKeyUpload;
}