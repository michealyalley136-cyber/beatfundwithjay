// Web polyfills for Expo modules
// This file patches expo-modules-core to add registerWebModule for web compatibility

// Patch immediately when this module loads
(function() {
  'use strict';
  
  if (typeof window === 'undefined') {
    return; // Not in browser
  }
  
  // Try to patch expo-modules-core if it's already loaded
  try {
    if (typeof require !== 'undefined') {
      const expoModulesCore = require('expo-modules-core');
      if (expoModulesCore && typeof expoModulesCore.registerWebModule === 'undefined') {
        expoModulesCore.registerWebModule = function(name, mod) {
          // No-op for web - modules are auto-registered
        };
      }
    }
  } catch (e) {
    // Module not loaded yet, will be patched when it loads
  }
  
  // Also patch via global if available
  if (typeof global !== 'undefined' && global.require) {
    try {
      const expoModulesCore = global.require('expo-modules-core');
      if (expoModulesCore && typeof expoModulesCore.registerWebModule === 'undefined') {
        expoModulesCore.registerWebModule = function() {};
      }
    } catch (e) {
      // Ignore
    }
  }
})();

