import firebaseAuthService from './firebaseAuth';
import githubKeyService from './githubKeyService';
import CryptoService from './cryptoService';

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
        console.log('Uploading public key to GitHub...');
        try {
          await githubKeyService.uploadPublicKey(keyPair.publicKey, githubToken);
          console.log('Public key uploaded successfully');
        } catch (keyError) {
          console.warn('Failed to upload key to GitHub:', keyError.message);
          // Continue anyway - user can upload manually
        }
      }
      
      return {
        success: true,
        user: user.data,
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
}

const authService = new AuthService();
export default authService;