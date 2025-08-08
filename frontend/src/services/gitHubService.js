// githubKeyService.js
import sshpk from 'sshpk';

class GitHubKeyService {
  async uploadPublicKey(publicKeyPem, githubToken, keyTitle = 'SecureChat Key') {
    try {
      const sshKey = this.convertPEMtoSSH(publicKeyPem); 

      const response = await fetch('https://api.github.com/user/keys', {
        method: 'POST',
        headers: {
          'Authorization': `token ${githubToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          title: `${keyTitle} - ${new Date().toISOString().split('T')[0]}`,
          key: sshKey
        })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(`GitHub API error: ${response.status} - ${error.message}`);
      }

      const keyData = await response.json();
      console.log(' Public key uploaded to GitHub:', keyData.id);
      return keyData;

    } catch (error) {
      console.error(' Failed to upload key to GitHub:', error);
      throw error;
    }
  }

  async fetchUserPublicKeys(githubUsername) {
    console.log('[GITHUB] Fetching SSH keys for GitHub user:', githubUsername);
    const url = `https://api.github.com/users/${githubUsername}/keys`;
    console.log('[GITHUB] API URL:', url);

    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/vnd.github+json' }
    });

    console.log('[GITHUB] Response status:', response.status);
    
    if (!response.ok) {
      if (response.status === 404) {
        console.error(' [GITHUB] User not found or has no public SSH keys');
        throw new Error(`GitHub user '${githubUsername}' not found or has no public SSH keys`);
      }
      throw new Error(`GitHub responded with ${response.status}`);
    }

    const keysData = await response.json();
    console.log('[GITHUB] Found', keysData.length, 'SSH keys');
    console.log(' [GITHUB] Keys data:', keysData);
    
    const rsaKeys = keysData
      .map(k => k.key)
      .filter(key => key.startsWith('ssh-rsa'));
      
    console.log('[GITHUB] RSA keys found:', rsaKeys.length);
    
    if (rsaKeys.length === 0) {
      throw new Error(`GitHub user '${githubUsername}' has no RSA SSH keys`);
    }
    
    return rsaKeys;
  }

  convertSSHtoPEM(sshKey) {
    try {
      const key = sshpk.parseKey(sshKey, 'ssh');
      return key.toString('pem');
    } catch (error) {
      throw new Error(`Failed to convert SSH to PEM: ${error.message}`);
    }
  }

  convertPEMtoSSH(pemKey) {
    try {
      const key = sshpk.parseKey(pemKey, 'pem');
      return key.toString('ssh');
    } catch (error) {
      throw new Error(`Failed to convert PEM to SSH: ${error.message}`);
    }
  }
}

export default new GitHubKeyService();