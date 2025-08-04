class GitHubKeyService {
  async uploadPublicKey(publicKeyPem, githubToken, keyTitle = 'SecureChat Key') {
    try {
      // Convert PEM to SSH format
      const sshKey = this.convertPEMtoSSH(publicKeyPem);
      
      // Upload to GitHub using the OAuth token from Firebase
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
      console.log('Public key uploaded to GitHub:', keyData.id);
      return keyData;
      
    } catch (error) {
      console.error('Failed to upload key to GitHub:', error);
      throw error;
    }
  }
  
  async fetchUserPublicKeys(githubUsername) {
    try {
      // Public API - no token needed
      const response = await fetch(`https://github.com/${githubUsername}.keys`);
      if (!response.ok) {
        throw new Error(`Failed to fetch keys for ${githubUsername}`);
      }
      
      const keysText = await response.text();
      const keys = keysText.split('\n').filter(key => key.trim());
      
      console.log(`Fetched ${keys.length} public keys for ${githubUsername}`);
      return keys;
    } catch (error) {
      console.error(`Error fetching keys for ${githubUsername}:`, error);
      throw error;
    }
  }
  
  convertPEMtoSSH(pemKey) {
    try {
      // Remove PEM headers and whitespace
      const base64Key = pemKey
        .replace(/-----BEGIN PUBLIC KEY-----/g, '')
        .replace(/-----END PUBLIC KEY-----/g, '')
        .replace(/\s/g, '');
      
      // For now, create a basic SSH format
      // In production, you'd need proper ASN.1 parsing
      return `ssh-rsa ${base64Key} user@securechat`;
    } catch (error) {
      console.error('PEM to SSH conversion failed:', error);
      throw new Error('Failed to convert PEM to SSH format');
    }
  }
  
  convertSSHtoPEM(sshKey) {
    try {
      // Extract the base64 part from SSH key
      const parts = sshKey.trim().split(' ');
      if (parts.length < 2) {
        throw new Error('Invalid SSH key format');
      }
      
      const base64Key = parts[1];
      
      // Convert to PEM format
      const pemKey = `-----BEGIN PUBLIC KEY-----\n${base64Key}\n-----END PUBLIC KEY-----`;
      return pemKey;
    } catch (error) {
      console.error('SSH to PEM conversion failed:', error);
      throw new Error('Failed to convert SSH to PEM format');
    }
  }
}

const githubKeyService = new GitHubKeyService();
export default githubKeyService;