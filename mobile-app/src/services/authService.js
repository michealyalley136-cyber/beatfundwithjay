import api from '../config/api';
import AsyncStorage from '@react-native-async-storage/async-storage';

export const authService = {
  // Login
  async login(identifier, password) {
    try {
      const response = await api.post('/api/auth/login', {
        identifier: identifier,
        password: password,
      });
      
      return { success: true, data: response.data };
    } catch (error) {
      throw error.response?.data || { message: error.message || 'Login failed' };
    }
  },

  // Register
  async register(userData) {
    try {
      const response = await api.post('/api/auth/register', userData);
      
      return { success: true, data: response.data };
    } catch (error) {
      throw error.response?.data || { message: error.message || 'Registration failed' };
    }
  },

  // Logout
  async logout() {
    try {
      // Clear storage - don't call API if not configured
      await AsyncStorage.multiRemove(['auth_token', 'csrf_token', 'user_data']);
      return { success: true };
    } catch (error) {
      // Clear storage even if there's an error
      try {
        await AsyncStorage.multiRemove(['auth_token', 'csrf_token', 'user_data']);
      } catch (e) {
        // Ignore errors
      }
      return { success: true };
    }
  },

  // Get current user
  async getCurrentUser() {
    try {
      const response = await api.get('/api/user/me');
      return response.data;
    } catch (error) {
      throw error.response?.data || { message: error.message || 'Failed to get user' };
    }
  },

  // Check if user is authenticated
  async checkAuth() {
    try {
      const token = await AsyncStorage.getItem('auth_token');
      if (!token) return null;
      
      const userData = await AsyncStorage.getItem('user_data');
      return userData ? JSON.parse(userData) : null;
    } catch (error) {
      return null;
    }
  },
};

