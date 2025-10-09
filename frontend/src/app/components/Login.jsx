'use client'
import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../context/AuthContext';
import Register from './Register';

function Login() {
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showSignup, setShowSignup] = useState(false);
  const [loginData, setLoginData] = useState({ email: '', password: '' });
  const router = useRouter();
  const { currentUser, login } = useAuth();

  // Redirect if already logged in
  useEffect(() => {
    if (currentUser) {
      router.push('/home');
    }
  }, [currentUser, router]);

  const handleManualLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Use the AuthContext login function
      await login(loginData.email, loginData.password);
      router.push('/home');
    } catch (error) {
      console.error("Login error:", error);
      setError(error.message || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleSignup = (user) => {
    // Store user data and redirect
    localStorage.setItem('currentUser', JSON.stringify({
      uid: user.uid || `manual_${user.email}`,
      email: user.email,
      displayName: user.name
    }));
    router.push('/home');
  };

  // Don't render login form if user is already authenticated
  if (currentUser) {
    return null;
  }

  if (showSignup) {
    return (
              <Register />
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h2 style={{color: '#007bff', textAlign: 'center'}}>Welcome Back</h2>
        
        {error && (
          <div style={styles.errorMessage}>
            {error}
          </div>
        )}
        
        <form onSubmit={handleManualLogin}>
          <input
            type="email"
            placeholder="Email"
            value={loginData.email}
            onChange={(e) => setLoginData({...loginData, email: e.target.value})}
            style={styles.input}
            required
          />
          
          <input
            type="password"
            placeholder="Password"
            value={loginData.password}
            onChange={(e) => setLoginData({...loginData, password: e.target.value})}
            style={styles.input}
            required
          />
          
          <button 
            type="submit"
            disabled={loading}
            style={{
              ...styles.button,
              opacity: loading ? 0.6 : 1,
              cursor: loading ? 'not-allowed' : 'pointer'
            }}
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
        
        <div style={styles.switchText}>
          Don't have an account?{' '}
          <button onClick={() => setShowSignup(true)} style={styles.switchButton}>
            Sign Up
          </button>
        </div>
      </div>
    </div>
  );
}

const styles = {
  container: {
    display: 'flex',
    height: '100vh',
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#1a1a1a',
  },
  card: {
    padding: 40,
    backgroundColor: '#2a2a2a',
    borderRadius: 10,
    boxShadow: '0 4px 20px rgba(0,0,0,0.3)',
    minWidth: '350px',
    color: 'white'
  },
  button: {
    width: '100%',
    padding: '12px 24px',
    backgroundColor: '#4285F4',
    color: '#fff',
    border: 'none',
    borderRadius: 5,
    cursor: 'pointer',
    fontSize: '16px',
    fontWeight: 'bold',
    transition: 'opacity 0.3s',
  },
  input: {
    width: '100%',
    padding: '12px',
    marginBottom: '15px',
    border: '1px solid #444',
    borderRadius: '5px',
    backgroundColor: '#1a1a1a',
    color: 'white',
    fontSize: '14px',
    boxSizing: 'border-box'
  },
  errorMessage: {
    backgroundColor: '#4d1a1a',
    color: '#ff6b6b',
    padding: '10px',
    borderRadius: '4px',
    marginBottom: '15px',
    fontSize: '14px'
  },
  switchText: {
    textAlign: 'center',
    marginTop: '20px',
    fontSize: '14px',
    color: '#888'
  },
  switchButton: {
    background: 'none',
    border: 'none',
    color: '#007bff',
    cursor: 'pointer',
    textDecoration: 'underline'
  }
};

export default Login;
