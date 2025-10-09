"use client"
import React, { createContext, useContext, useEffect, useState } from 'react';

const AuthContext = createContext();

export function useAuth() {
  return useContext(AuthContext);
}

export function AuthProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);

  async function register(email, password, name, username) {
    try {
      const response = await fetch('http://localhost:5001/api/auth/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password,
          name,
          username
        }),
      });

      const data = await response.json();

      if (data.status === 'success') {
        // Create user object for frontend
        const user = {
          uid: data.user.id,
          email: data.user.email,
          displayName: data.user.name,
          username: data.user.username
        };
        
        setCurrentUser(user);
        localStorage.setItem('currentUser', JSON.stringify(user));
        return user;
      } else {
        throw new Error(data.message || 'Registration failed');
      }
    } catch (error) {
      console.error('Registration error:', error);
      throw error;
    }
  }

  async function login(email, password) {
    try {
      const response = await fetch('http://localhost:5001/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password
        }),
      });

      const data = await response.json();

      if (data.status === 'success') {
        // Create user object for frontend
        const user = {
          uid: data.user.id,
          email: data.user.email,
          displayName: data.user.name,
          username: data.user.username
        };
        
        setCurrentUser(user);
        localStorage.setItem('currentUser', JSON.stringify(user));
        return user;
      } else {
        throw new Error(data.message || 'Login failed');
      }
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  }

  async function logout() {
    try {
      setCurrentUser(null);
      localStorage.removeItem('currentUser');
    } catch (error) {
      console.error('Logout error:', error);
      throw error;
    }
  }

  useEffect(() => {
    // Check for existing user in localStorage
    const savedUser = localStorage.getItem('currentUser');
    if (savedUser) {
      try {
        const user = JSON.parse(savedUser);
        setCurrentUser(user);
      } catch (error) {
        console.error('Error parsing saved user:', error);
        localStorage.removeItem('currentUser');
      }
    }
    setLoading(false);
  }, []);

  const value = {
    currentUser,
    register,
    login,
    logout,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
}