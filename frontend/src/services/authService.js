import firebaseAuthService from './firebaseAuth';
import githubKeyService from './gitHubService';
import CryptoService from './cryptoService';
import { manualKeyUpload } from '../utils/manualKeyUpload';

class AuthService {
  async loginWithGitHub() {
    try {
      console.log('Starting GitHub OAuth login...');
      
      // 1. Firebase GitHub OAuth
      const { user, githubToken, firebaseToken } = await firebaseAuthService.signInWithGitHub();
      
      if (user.status === 'error') {
        throw new Error(user.message);
      }
      
      console.log('GitHub OAuth successful:', user.data.github_username);
      
      // 2. Generate RSA keys
      console.log('Generating RSA key pair...');
      const keyPair = await CryptoService.generateRSAKeyPair();
      
      // 3. Store private key locally
      localStorage.setItem('private_key', keyPair.privateKey);
      localStorage.setItem('github_username', user.data.github_username);
      localStorage.setItem('github_token', githubToken);
      localStorage.setItem('user_data', JSON.stringify(user.data));
      
      // 4. Upload public key to GitHub
      if (user.data.github_username && githubToken) {
        console.log('[AUTH] Uploading public key to GitHub for user:', user.data.github_username);
        console.log('[AUTH] GitHub token available:', !!githubToken);
        console.log('[AUTH] Public key preview:', keyPair.publicKey.substring(0, 50) + '...');
        
        let uploadSuccess = false;
        
        try {
          const uploadResult = await githubKeyService.uploadPublicKey(keyPair.publicKey, githubToken);
          console.log('[AUTH] Public key uploaded successfully:', uploadResult.id);
          uploadSuccess = true;
          
        } catch (keyError) {
          console.error('[AUTH] Upload failed:', keyError.message);
          
          // If upload fails, try with a fresh token
          try {
            console.log('[AUTH] Retrying with fresh token...');
            const newAuth = await firebaseAuthService.signInWithGitHub();
            const freshToken = newAuth.githubToken;
            
            if (freshToken !== githubToken) {
              const retryResult = await githubKeyService.uploadPublicKey(keyPair.publicKey, freshToken);
              console.log('[AUTH] Retry successful:', retryResult.id);
              localStorage.setItem('github_token', freshToken);
              uploadSuccess = true;
            }
          } catch (retryError) {
            console.error('[AUTH] Retry failed:', retryError.message);
          }
        }
        
        // Verify upload worked
        if (uploadSuccess) {
          setTimeout(async () => {
            try {
              const keys = await githubKeyService.fetchUserPublicKeys(user.data.github_username);
              console.log('[AUTH] Verified:', keys.length, 'SSH keys on GitHub');
            } catch (verifyError) {
              console.error('[AUTH]  Verification failed - key may not be uploaded');
            }
          }, 1000);
        } else {
          console.error(' [AUTH]  SSH key upload completely failed');
        }
      } else {
        console.warn('[AUTH] Missing GitHub username or token for key upload');
        console.log('[AUTH] user.data.github_username:', user.data.github_username);
        console.log('[AUTH] githubToken:', !!githubToken);
      }
      
      return {
        success: true,
        user: {
          ...user.data,
          uid: String(user.data.id)
        },
        message: 'Login successful'
      };
      
    } catch (error) {
      console.error('GitHub login failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  async logout() {
    try {
      await firebaseAuthService.signOut();
      
      // Clear all stored data
      localStorage.removeItem('private_key');
      localStorage.removeItem('github_username');
      localStorage.removeItem('github_token');
      localStorage.removeItem('user_data');
      
      return { success: true };
    } catch (error) {
      console.error('Logout failed:', error);
      return { success: false, error: error.message };
    }
  }
  
  getCurrentUser() {
    try {
      const userData = localStorage.getItem('user_data');
      return userData ? JSON.parse(userData) : null;
    } catch (error) {
      console.error('Failed to get current user:', error);
      return null;
    }
  }
  
  isAuthenticated() {
    return !!this.getCurrentUser();
  }
  
  getGitHubToken() {
    return localStorage.getItem('github_token');
  }
  
  getPrivateKey() {
    return localStorage.getItem('private_key');
  }
  
  // Manual key upload for testing
  async manualKeyUpload() {
    return await manualKeyUpload();
  }
}

const authService = new AuthService();
export default authService;