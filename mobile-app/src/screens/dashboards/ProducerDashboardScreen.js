import React from 'react';
import { View, StyleSheet, ScrollView } from 'react-native';
import { Text, Button, Surface } from 'react-native-paper';
import { Ionicons } from '@expo/vector-icons';
import { useAuth } from '../../context/AuthContext';
import Card from '../../components/Card';
import StatCard from '../../components/StatCard';
import QuickActionButton from '../../components/QuickActionButton';

export default function ProducerDashboardScreen({ navigation }) {
  const { user } = useAuth();

  return (
    <ScrollView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Producer Dashboard</Text>
        <Text style={styles.subtitle}>Welcome, @{user?.username}</Text>
      </View>

      {/* Stats Row */}
      <View style={styles.statsRow}>
        <StatCard label="Wallet Balance" value="$0.00" />
        <StatCard label="Beats Sold" value="0" />
        <StatCard label="Bookings" value="0" />
      </View>

      {/* Quick Actions */}
      <Card title="Quick Actions">
        <View style={styles.quickActions}>
          <QuickActionButton
            icon="add-circle"
            label="Upload Beat"
            onPress={() => {}}
          />
          <QuickActionButton
            icon="musical-notes"
            label="My Catalog"
            onPress={() => {}}
          />
          <QuickActionButton
            icon="calendar"
            label="Booking Requests"
            onPress={() => {}}
          />
          <QuickActionButton
            icon="wallet"
            label="Wallet"
            onPress={() => navigation.navigate('Wallet')}
          />
        </View>
      </Card>

      {/* Booking Requests */}
      <Card title="Recent Booking Requests">
        <View style={styles.emptyState}>
          <Ionicons name="calendar-outline" size={48} color="#9ca3af" />
          <Text style={styles.emptyText}>No booking requests</Text>
        </View>
      </Card>

      {/* Project Vaults */}
      <Card title="Project Vaults">
        <View style={styles.emptyState}>
          <Ionicons name="folder-outline" size={48} color="#9ca3af" />
          <Text style={styles.emptyText}>No active vaults</Text>
          <Button
            mode="contained"
            style={styles.button}
            onPress={() => {}}
          >
            Create Vault
          </Button>
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
    marginBottom: 16,
  },
  button: {
    marginTop: 8,
  },
});

