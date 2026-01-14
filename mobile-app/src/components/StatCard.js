import React from 'react';
import { View, StyleSheet } from 'react-native';
import { Surface, Text } from 'react-native-paper';

export default function StatCard({ label, value, icon, style }) {
  return (
    <Surface style={[styles.card, style]}>
      {icon && <View style={styles.iconContainer}>{icon}</View>}
      <Text style={styles.label}>{label}</Text>
      <Text style={styles.value}>{value}</Text>
    </Surface>
  );
}

const styles = StyleSheet.create({
  card: {
    padding: 16,
    backgroundColor: 'rgba(255, 255, 255, 0.06)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.12)',
    borderRadius: 12,
    minWidth: 120,
  },
  iconContainer: {
    marginBottom: 8,
  },
  label: {
    fontSize: 12,
    color: '#9ca3af',
    marginBottom: 4,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  value: {
    fontSize: 24,
    fontWeight: '700',
    color: '#e5e7eb',
  },
});

