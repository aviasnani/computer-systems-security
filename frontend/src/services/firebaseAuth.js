import { signInWithPopup, GithubAuthProvider } from 'firebase/auth';
import { auth } from '../firebase.config'; // Use existing config

class FirebaseAuthService {
  async signInWithGitHub() {
    try {
      const provider = new GithubAuthProvider();
      
      // Request additional scopes for GitHub API access
      provider.addScope('user:email');
      provider.addScope('public_repo'); // For uploading keys later
      
      const result = await signInWithPopup(auth, provider);
      
      // Get GitHub access token from credential
      const credential = GithubAuthProvider.credentialFromResult(result);
      const githubToken = credential.accessToken;
      
      // Get Firebase ID token
      const idToken = await result.user.getIdToken();
      
      // Send to your backend
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ firebase_token: idToken })
      });
      
      const userData = await response.json();
      
      return {
        user: userData,
        githubToken, // for uploading public keys to github later
        firebaseToken: idToken
      };
      
    } catch (error) {
      console.error('GitHub sign-in failed:', error);
      throw new Error(`GitHub sign-in failed: ${error.message}`);
    }
  }
  
  async signOut() {
    try {
      await auth.signOut();
      // Clear any stored tokens
      localStorage.removeItem('github_token');
      localStorage.removeItem('private_key');
    } catch (error) {
      console.error('Sign out failed:', error);
    }
  }
}

const firebaseAuthService = new FirebaseAuthService();
export default firebaseAuthService;
