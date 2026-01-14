# BeatFund Mobile App

React Native mobile application for BeatFund platform, built with Expo.

## Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- Expo CLI: `npm install -g expo-cli`
- For iOS: Xcode (Mac only)
- For Android: Android Studio

## Installation

1. Install dependencies:
```bash
cd mobile-app
npm install
```

2. Update API configuration:
   - Open `src/config/api.js`
   - Update `API_BASE_URL` to point to your Flask backend
   - For local testing: Use your computer's IP address (e.g., `http://192.168.1.100:5000`)

## Running the App

### Development Mode
```bash
npm start
```

Then:
- Press `i` for iOS simulator
- Press `a` for Android emulator
- Scan QR code with Expo Go app on your physical device

### iOS
```bash
npm run ios
```

### Android
```bash
npm run android
```

## Project Structure

```
mobile-app/
├── src/
│   ├── config/          # Configuration files
│   │   └── api.js       # API client setup
│   ├── context/         # React Context providers
│   │   └── AuthContext.js
│   ├── navigation/      # Navigation setup
│   │   ├── AuthNavigator.js
│   │   └── MainNavigator.js
│   ├── screens/         # Screen components
│   │   ├── auth/
│   │   │   ├── LoginScreen.js
│   │   │   └── RegisterScreen.js
│   │   ├── DashboardScreen.js
│   │   ├── MarketScreen.js
│   │   ├── WalletScreen.js
│   │   └── ProfileScreen.js
│   └── services/        # API service functions
│       └── authService.js
├── App.js               # Main app component
├── app.json             # Expo configuration
└── package.json
```

## Backend API Requirements

Your Flask backend needs to provide JSON API endpoints. Currently, the Flask app returns HTML. You'll need to:

1. Create API endpoints that return JSON:
   - `/api/login` - POST - Returns `{user: {...}, token: "..."}`
   - `/api/register` - POST - Returns `{user: {...}, token: "..."}`
   - `/api/user/me` - GET - Returns current user data
   - `/api/logout` - GET/POST - Logs out user

2. Update CORS settings in Flask to allow mobile app requests

3. Consider using Flask-RESTful or Flask-RESTX for better API structure

## Next Steps

1. **Add API endpoints to Flask backend** for mobile app
2. **Implement remaining screens**:
   - Producer Dashboard
   - Studio Dashboard
   - Market/Browse
   - Wallet details
   - BookMe features
   - Project Vaults

3. **Add features**:
   - Image uploads
   - Audio playback
   - Push notifications
   - Offline support

4. **Testing**:
   - Test on physical devices
   - Test on both iOS and Android
   - Handle network errors gracefully

## Building for Production

### iOS
```bash
expo build:ios
```

### Android
```bash
expo build:android
```

Or use EAS Build (recommended):
```bash
npm install -g eas-cli
eas build:configure
eas build --platform ios
eas build --platform android
```

## Notes

- The app uses React Native Paper for UI components
- Authentication state is managed with Context API
- API calls use Axios with interceptors for token management
- The app is designed to work with your existing Flask backend

