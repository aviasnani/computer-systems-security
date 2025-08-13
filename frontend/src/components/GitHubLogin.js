import React, { useState } from 'react';
import authService from '../services/authService';

const GitHubLogin = ({ onLoginSuccess }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  const handleGitHubLogin = async () => {
    setLoading(true);
    setError('');
    
    try {
      const result = await authService.loginWithGitHub();
      
      if (result.success) {
        console.log('Login successful:', result.user);
        if (onLoginSuccess) {
          onLoginSuccess(result.user);
        }
      } else {
        setError(result.error || 'Login failed');
      }
    } catch (error) {
      setError('Login failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div style={{ 
      display: 'flex', 
      flexDirection: 'column', 
      alignItems: 'center', 
      padding: '2rem',
      maxWidth: '400px',
      margin: '0 auto'
    }}>
      <h2>SecureChat Login</h2>
      <p style={{ textAlign: 'center', color: '#666', marginBottom: '2rem' }}>
        Sign in with GitHub to enable end-to-end encrypted messaging
      </p>
      
      {error && (
        <div style={{ 
          color: 'red', 
          marginBottom: '1rem',
          padding: '0.5rem',
          border: '1px solid red',
          borderRadius: '4px',
          backgroundColor: '#ffebee'
        }}>
          {error}
        </div>
      )}
      
      <button 
        onClick={handleGitHubLogin}
        disabled={loading}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.75rem 1.5rem',
          fontSize: '1rem',
          backgroundColor: '#24292e',
          color: 'white',
          border: 'none',
          borderRadius: '6px',
          cursor: loading ? 'not-allowed' : 'pointer',
          opacity: loading ? 0.7 : 1
        }}
      >
        {loading ? (
          <>
            <span>🔄</span>
            Signing in...
          </>
        ) : (
          <>
            <span>🐙</span>
            Continue with GitHub
          </>
        )}
      </button>
      
      <div style={{ marginTop: '1rem', fontSize: '0.8rem', color: '#666' }}>
        <p>✅ End-to-end encryption</p>
        <p>✅ GitHub identity verification</p>
        <p>✅ No server-side key storage</p>
      </div>
    </div>
  );
};

export default GitHubLogin;