import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';

// Update this to your Flask backend URL
// For local development (web): 'http://localhost:5000'
// For physical device: Use your computer's IP (e.g., 'http://192.168.100.105:5000')
// For production: 'https://your-backend-url.com'
// Run 'ipconfig' in PowerShell to find your IP address
const API_BASE_URL = __DEV__ 
  ? 'http://localhost:5000'  // Change to your Flask backend URL
  : 'https://your-backend-url.com';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Handle case where API_BASE_URL is not configured
if (!API_BASE_URL) {
  console.warn('⚠️ API_BASE_URL is not configured. Using mock data. Update src/config/api.js with your backend URL.');
}

// Request interceptor to add auth token
api.interceptors.request.use(
  async (config) => {
    // Skip if API is not configured - allow request to proceed for mock mode
    if (!API_BASE_URL) {
      return config;
    }
    
    try {
      const token = await AsyncStorage.getItem('auth_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      // Get CSRF token if available
      const csrfToken = await AsyncStorage.getItem('csrf_token');
      if (csrfToken) {
        config.headers['X-CSRFToken'] = csrfToken;
      }
    } catch (error) {
      console.error('Error getting auth token:', error);
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    // Handle network errors gracefully - don't throw if API is not configured
    if (!API_BASE_URL) {
      // Silently handle errors when API is not configured
      return Promise.resolve({ data: { mock: true, error: 'API not configured' } });
    }
    
    // Handle network errors
    if (error.code === 'ECONNABORTED' || error.message === 'Network Error' || !error.response) {
      console.warn('⚠️ Network error - backend may not be running');
      return Promise.resolve({ data: { mock: true, error: 'Network error' } });
    }
    
    if (error.response?.status === 401) {
      // Unauthorized - clear tokens and redirect to login
      await AsyncStorage.multiRemove(['auth_token', 'csrf_token', 'user_data']);
      // Navigation will be handled by AuthContext
    }
    return Promise.reject(error);
  }
);

export default api;
