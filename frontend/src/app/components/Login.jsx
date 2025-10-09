'use client'
import React, { useState, useEffect } from 'react';
import { signInWithPopup } from 'firebase/auth';
import { auth, googleProvider } from '../../firebase.config';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../context/AuthContext';
import Signup from './Signup';

function Login() {
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showSignup, setShowSignup] = useState(false);
  const [manualLogin, setManualLogin] = useState(false);
  const [loginData, setLoginData] = useState({ email: '', password: '' });
  const router = useRouter();
  const { currentUser } = useAuth();

  // Redirect if already logged in
  useEffect(() => {
    if (currentUser) {
      router.push('/home');
    }
  }, [currentUser, router]);

  const handleLogin = async (provider) => {
    try {
      setError('');
      setLoading(true);
      
      const result = await signInWithPopup(auth, provider);
      
      if (result.user) {
        // Get Firebase ID token
        const idToken = await result.user.getIdToken();
        
        // Send token to backend
        const response = await fetch('http://localhost:5000/api/auth/firebase', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({ firebaseToken: idToken })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
          console.log("Successfully logged in:", data.data);
          router.push('/home');
        } else {
          setError(data.message || 'Authentication failed');
        }
      } else {
        setError('Sign-in failed. Please try again.');
      }
      
    } catch (error) {
      console.error("Login error:", error);
      
      
      let errorMessage = 'Failed to sign in. Please try again.';
      
      switch (error.code) {
        case 'auth/popup-closed-by-user':
          errorMessage = 'Sign-in was cancelled. Please try again.';
          break;
        case 'auth/popup-blocked':
          errorMessage = 'Pop-up was blocked. Please allow pop-ups and try again.';
          break;
        case 'auth/network-request-failed':
          errorMessage = 'Network error. Please check your connection and try again.';
          break;
        case 'auth/too-many-requests':
          errorMessage = 'Too many failed attempts. Please try again later.';
          break;
        default:
          errorMessage = 'Error in signing in. Please try again.';
      }
      
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleManualLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('http://localhost:5000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginData)
      });

      const data = await response.json();

      if (data.status === 'success') {
        // Store user data in localStorage for the app
        localStorage.setItem('currentUser', JSON.stringify({
          uid: data.user.uid,
          email: data.user.email,
          displayName: data.user.name
        }));
        router.push('/home');
      } else {
        setError(data.message);
      }
    } catch (error) {
      setError('Login failed. Please try again.');
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
      <Signup 
        onSignup={handleSignup}
        onSwitchToLogin={() => setShowSignup(false)}
      />
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
        
        {!manualLogin ? (
          <>
            <button 
              onClick={() => handleLogin(googleProvider)} 
              style={{
                ...styles.button,
                opacity: loading ? 0.6 : 1,
                cursor: loading ? 'not-allowed' : 'pointer',
                marginBottom: '15px'
              }}
              disabled={loading}
            >
              {loading ? 'Signing in...' : 'Sign In with Google'}
            </button>
            
            <div style={{textAlign: 'center', margin: '15px 0', color: '#888'}}>or</div>
            
            <button 
              onClick={() => setManualLogin(true)}
              style={{...styles.button, backgroundColor: '#28a745'}}
            >
              Sign In with Email
            </button>
            
            <div style={styles.switchText}>
              Don't have an account?{' '}
              <button onClick={() => setShowSignup(true)} style={styles.switchButton}>
                Sign Up
              </button>
            </div>
          </>
        ) : (
          <>
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
            
            <button 
              onClick={() => setManualLogin(false)}
              style={{...styles.switchButton, marginTop: '15px', display: 'block', margin: '15px auto 0'}}
            >
              Back to options
            </button>
          </>
        )}
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
