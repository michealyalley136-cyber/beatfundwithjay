import React from 'react';
import { View, StyleSheet } from 'react-native';
import ArtistDashboardScreen from './dashboards/ArtistDashboardScreen';
import ProducerDashboardScreen from './dashboards/ProducerDashboardScreen';
import StudioDashboardScreen from './dashboards/StudioDashboardScreen';
import EngineerDashboardScreen from './dashboards/EngineerDashboardScreen';
import { useAuth } from '../context/AuthContext';

export default function DashboardScreen({ navigation }) {
  const { user } = useAuth();
  const role = user?.primary_role || 'artist';

  // Route to role-specific dashboard
  switch (role) {
    case 'artist':
      return <ArtistDashboardScreen navigation={navigation} />;
    case 'producer':
      return <ProducerDashboardScreen navigation={navigation} />;
    case 'studio':
      return <StudioDashboardScreen navigation={navigation} />;
    case 'engineer':
    case 'mix_master_engineer':
      return <EngineerDashboardScreen navigation={navigation} />;
    default:
      return <ArtistDashboardScreen navigation={navigation} />;
  }
}


