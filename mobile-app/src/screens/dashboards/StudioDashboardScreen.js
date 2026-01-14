import React from 'react';
import { View, StyleSheet, ScrollView } from 'react-native';
import { Text, Button, Surface } from 'react-native-paper';
import { Ionicons } from '@expo/vector-icons';
import { useAuth } from '../../context/AuthContext';
import Card from '../../components/Card';
import StatCard from '../../components/StatCard';
import QuickActionButton from '../../components/QuickActionButton';

export default function StudioDashboardScreen({ navigation }) {
  const { user } = useAuth();

  return (
    <ScrollView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Studio Dashboard</Text>
        <Text style={styles.subtitle}>Welcome, @{user?.username}</Text>
      </View>

      {/* Stats Row */}
      <View style={styles.statsRow}>
        <StatCard label="Wallet Balance" value="$0.00" />
        <StatCard label="Bookings" value="0" />
        <StatCard label="Availability" value="Open" />
      </View>

      {/* Quick Actions */}
      <Card title="Quick Actions">
        <View style={styles.quickActions}>
          <QuickActionButton
            icon="calendar"
            label="Booking Requests"
            onPress={() => {}}
          />
          <QuickActionButton
            icon="time"
            label="Set Availability"
            onPress={() => {}}
          />
          <QuickActionButton
            icon="images"
            label="Portfolio"
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

      {/* Availability Status */}
      <Card title="Availability Status">
        <View style={styles.availabilityCard}>
          <View style={styles.availabilityRow}>
            <Ionicons name="checkmark-circle" size={24} color="#22c55e" />
            <Text style={styles.availabilityText}>Studio is available</Text>
          </View>
          <Button
            mode="outlined"
            style={styles.button}
            onPress={() => {}}
          >
            Manage Schedule
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
  },
  availabilityCard: {
    padding: 8,
  },
  availabilityRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16,
  },
  availabilityText: {
    fontSize: 16,
    color: '#e5e7eb',
    marginLeft: 12,
  },
  button: {
    marginTop: 8,
  },
});

