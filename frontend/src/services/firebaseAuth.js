import { signInWithPopup, GithubAuthProvider } from 'firebase/auth';
import { auth } from '../firebase.config';

class FirebaseAuthService {
  async signInWithGitHub() {
    try {
      const provider = new GithubAuthProvider();
      provider.addScope('user:username');
      provider.addScope('public_repo');
      provider.addScope('write:public_key'); // 👈 necessary!

      const result = await signInWithPopup(auth, provider);

      const githubUsername = 
        result?.additionalUserInfo?.profile?.login ||
        result?.additionalUserInfo?.username ||
        result?.user?.reloadUserInfo?.screenName ||
        result?.user?.providerData?.[0]?.displayName ||
        result?.user?.displayName;

      if (!githubUsername) {
        throw new Error('Could not determine GitHub username from login');
      }

      const credential = GithubAuthProvider.credentialFromResult(result);
      const githubToken = credential.accessToken;
      const idToken = await result.user.getIdToken();

      // Store basic data
      localStorage.setItem('github_username', githubUsername);

      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/auth/login`,  {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ firebase_token: idToken })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Backend error: ${response.status} - ${errorText}`);
      }

      const userData = await response.json();

      return {
        user: userData,
        githubToken,
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
      localStorage.removeItem('github_token');
      localStorage.removeItem('private_key');
    } catch (error) {
      console.error('Sign out failed:', error);
    }
  }
}

export default new FirebaseAuthService();
