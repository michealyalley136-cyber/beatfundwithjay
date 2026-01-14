import React, { createContext, useState, useEffect, useContext } from 'react';
import { authService } from '../services/authService';
import AsyncStorage from '@react-native-async-storage/async-storage';

const AuthContext = createContext({});

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const userData = await authService.checkAuth();
      if (userData) {
        setUser(userData);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const login = async (identifier, password) => {
    try {
      const response = await authService.login(identifier, password);
      // Store user data
      if (response.data?.user) {
        await AsyncStorage.setItem('user_data', JSON.stringify(response.data.user));
        await AsyncStorage.setItem('auth_token', response.data.token || 'session');
        setUser(response.data.user);
        return { success: true };
      }
      throw new Error('Invalid response');
    } catch (error) {
      return { success: false, error: error.message || 'Login failed' };
    }
  };

  const register = async (userData) => {
    try {
      const response = await authService.register(userData);
      if (response.data?.user) {
        await AsyncStorage.setItem('user_data', JSON.stringify(response.data.user));
        await AsyncStorage.setItem('auth_token', response.data.token || 'session');
        setUser(response.data.user);
        return { success: true };
      }
      throw new Error('Invalid response');
    } catch (error) {
      return { success: false, error: error.message || 'Registration failed' };
    }
  };

  const logout = async () => {
    try {
      await authService.logout();
      setUser(null);
      return { success: true };
    } catch (error) {
      setUser(null);
      return { success: true };
    }
  };

  const value = {
    user,
    loading,
    login,
    register,
    logout,
    checkAuthStatus,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

