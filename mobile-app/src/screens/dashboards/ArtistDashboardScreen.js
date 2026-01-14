import React from 'react';
import { View, StyleSheet, ScrollView } from 'react-native';
import { Text, Button, Surface } from 'react-native-paper';
import { Ionicons } from '@expo/vector-icons';
import { useAuth } from '../../context/AuthContext';
import Card from '../../components/Card';
import StatCard from '../../components/StatCard';
import QuickActionButton from '../../components/QuickActionButton';

export default function ArtistDashboardScreen({ navigation }) {
  const { user } = useAuth();

  return (
    <ScrollView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Artist Dashboard</Text>
        <Text style={styles.subtitle}>Welcome, @{user?.username}</Text>
      </View>

      {/* Stats Row */}
      <View style={styles.statsRow}>
        <StatCard label="Wallet Balance" value="$0.00" />
        <StatCard label="Active Projects" value="0" />
        <StatCard label="Bookings" value="0" />
      </View>

      {/* Quick Actions */}
      <Card title="Quick Actions">
        <View style={styles.quickActions}>
          <QuickActionButton
            icon="musical-notes"
            label="Browse Beats"
            onPress={() => navigation.navigate('Market')}
          />
          <QuickActionButton
            icon="calendar"
            label="Book Services"
            onPress={() => navigation.navigate('BookMe')}
          />
          <QuickActionButton
            icon="wallet"
            label="Wallet"
            onPress={() => navigation.navigate('Wallet')}
          />
          <QuickActionButton
            icon="folder"
            label="My Projects"
            onPress={() => {}}
          />
        </View>
      </Card>

      {/* Recent Activity */}
      <Card title="Recent Activity">
        <View style={styles.emptyState}>
          <Ionicons name="document-text-outline" size={48} color="#9ca3af" />
          <Text style={styles.emptyText}>No recent activity</Text>
        </View>
      </Card>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#020617',
  },
  header: {
    padding: 20,
    paddingTop: 60,
  },
  title: {
    fontSize: 32,
    fontWeight: '800',
    color: '#e5e7eb',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 16,
    color: '#9ca3af',
  },
  statsRow: {
    flexDirection: 'row',
    paddingHorizontal: 16,
    gap: 12,
    marginBottom: 8,
  },
  quickActions: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 12,
  },
  emptyState: {
    alignItems: 'center',
    padding: 32,
  },
  emptyText: {
    marginTop: 16,
    fontSize: 16,
    color: '#9ca3af',
  },
});

