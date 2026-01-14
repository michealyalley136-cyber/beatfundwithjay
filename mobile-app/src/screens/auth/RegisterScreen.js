import React, { useState } from 'react';
import {
  View,
  StyleSheet,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  Alert,
} from 'react-native';
import { Text, TextInput, Button, Surface } from 'react-native-paper';
import { useAuth } from '../../context/AuthContext';

const ROLES = [
  { label: 'Artist', value: 'artist' },
  { label: 'Producer', value: 'producer' },
  { label: 'Studio', value: 'studio' },
  { label: 'Engineer', value: 'engineer' },
  { label: 'Videographer', value: 'videographer' },
  { label: 'Designer', value: 'designer' },
];

export default function RegisterScreen({ navigation }) {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirm: '',
    role: 'artist',
    full_name: '',
    artist_name: '',
  });
  const [loading, setLoading] = useState(false);
  const { register } = useAuth();

  const handleRegister = async () => {
    // Validation
    if (!formData.username || !formData.email || !formData.password) {
      Alert.alert('Error', 'Please fill in all required fields');
      return;
    }

    if (formData.password !== formData.confirm) {
      Alert.alert('Error', 'Passwords do not match');
      return;
    }

    if (formData.password.length < 8) {
      Alert.alert('Error', 'Password must be at least 8 characters');
      return;
    }

    setLoading(true);
    const result = await register(formData);
    setLoading(false);

    if (!result.success) {
      Alert.alert('Registration Failed', result.error || 'Registration failed');
    }
  };

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      style={styles.container}
    >
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <View style={styles.header}>
          <Text style={styles.title}>BEATFUND</Text>
          <Text style={styles.subtitle}>Create Your Account</Text>
        </View>

        <Surface style={styles.form}>
          <Text style={styles.formTitle}>Sign Up</Text>

          <TextInput
            label="Username *"
            value={formData.username}
            onChangeText={(text) => setFormData({ ...formData, username: text })}
            mode="outlined"
            style={styles.input}
            autoCapitalize="none"
            autoComplete="username"
          />

          <TextInput
            label="Email *"
            value={formData.email}
            onChangeText={(text) => setFormData({ ...formData, email: text })}
            mode="outlined"
            style={styles.input}
            autoCapitalize="none"
            autoComplete="email"
            keyboardType="email-address"
            textContentType="emailAddress"
          />

          <TextInput
            label="Full Name"
            value={formData.full_name}
            onChangeText={(text) => setFormData({ ...formData, full_name: text })}
            mode="outlined"
            style={styles.input}
          />

          <TextInput
            label="Artist Name"
            value={formData.artist_name}
            onChangeText={(text) => setFormData({ ...formData, artist_name: text })}
            mode="outlined"
            style={styles.input}
          />

          <TextInput
            label="Password *"
            value={formData.password}
            onChangeText={(text) => setFormData({ ...formData, password: text })}
            mode="outlined"
            secureTextEntry
            style={styles.input}
            textContentType="password"
          />

          <TextInput
            label="Confirm Password *"
            value={formData.confirm}
            onChangeText={(text) => setFormData({ ...formData, confirm: text })}
            mode="outlined"
            secureTextEntry
            style={styles.input}
            textContentType="password"
          />

          <View style={styles.roleSelector}>
            <Text style={styles.roleLabel}>Role *</Text>
            <View style={styles.roleButtons}>
              {ROLES.map((role) => (
                <Button
                  key={role.value}
                  mode={formData.role === role.value ? 'contained' : 'outlined'}
                  onPress={() => setFormData({ ...formData, role: role.value })}
                  style={styles.roleButton}
                  compact
                >
                  {role.label}
                </Button>
              ))}
            </View>
          </View>

          <Button
            mode="contained"
            onPress={handleRegister}
            loading={loading}
            disabled={loading}
            style={styles.button}
            contentStyle={styles.buttonContent}
          >
            Sign Up
          </Button>

          <Button
            mode="text"
            onPress={() => navigation.navigate('Login')}
            style={styles.linkButton}
          >
            Already have an account? Log in
          </Button>
        </Surface>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#020617',
  },
  scrollContent: {
    flexGrow: 1,
    justifyContent: 'center',
    padding: 20,
  },
  header: {
    alignItems: 'center',
    marginBottom: 40,
  },
  title: {
    fontSize: 28,
    fontWeight: '800',
    color: '#e5e7eb',
    letterSpacing: 4,
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 14,
    color: '#9ca3af',
    letterSpacing: 2,
  },
  form: {
    padding: 24,
    borderRadius: 16,
    backgroundColor: 'rgba(255, 255, 255, 0.06)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.12)',
  },
  formTitle: {
    fontSize: 24,
    fontWeight: '700',
    color: '#e5e7eb',
    marginBottom: 24,
  },
  input: {
    marginBottom: 16,
    backgroundColor: 'rgba(0, 0, 0, 0.2)',
  },
  button: {
    marginTop: 8,
    marginBottom: 16,
    backgroundColor: '#22c55e',
  },
  buttonContent: {
    paddingVertical: 8,
  },
  linkButton: {
    marginTop: 8,
  },
  roleSelector: {
    marginBottom: 16,
  },
  roleLabel: {
    fontSize: 14,
    color: '#9ca3af',
    marginBottom: 8,
  },
  roleButtons: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
  roleButton: {
    marginRight: 8,
    marginBottom: 8,
  },
});

