import React from 'react';
import { View, ActivityIndicator, StyleSheet } from 'react-native';
import { Text } from 'react-native-paper';

export default function LoadingScreen() {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>BeatFund</Text>
      <ActivityIndicator size="large" color="#22c55e" style={styles.loader} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#020617',
    justifyContent: 'center',
    alignItems: 'center',
  },
  title: {
    fontSize: 32,
    fontWeight: '800',
    color: '#e5e7eb',
    letterSpacing: 4,
    marginBottom: 40,
  },
  loader: {
    marginTop: 20,
  },
});

