import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { User, BackupHistoryEntry } from '../types';

export const DEFAULT_SUPABASE_URL = 'https://vctjxlncglyisbqlidon.supabase.co';
export const DEFAULT_SUPABASE_ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZjdGp4bG5jZ2x5aXNicWxpZG9uIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTQyMDgwNzgsImV4cCI6MjEwOTc4NDA3OH0.A9fFVjXiBJIL8UweTduFimkJMcYh9MjgKsLAyE60ygA';

const SUPABASE_URL_KEY = 'infosec_supabase_url_custom';
const SUPABASE_KEY_KEY = 'infosec_supabase_anon_key_custom';

export function normalizeSupabaseUrl(url: string): string {
  if (!url) return '';
  return url.trim().replace(/\/rest\/v1\/?$/, '').replace(/\/$/, '');
}

export interface SupabaseConfig {
  url: string;
  anonKey: string;
  isConfigured: boolean;
  source: 'env' | 'custom' | 'default';
}

export function getSupabaseConfig(): SupabaseConfig {
  const customUrl = localStorage.getItem(SUPABASE_URL_KEY);
  const customKey = localStorage.getItem(SUPABASE_KEY_KEY);

  if (customUrl && customKey) {
    return {
      url: normalizeSupabaseUrl(customUrl),
      anonKey: customKey.trim(),
      isConfigured: true,
      source: 'custom',
    };
  }

  const envUrl = (import.meta.env.VITE_SUPABASE_URL as string) || '';
  const envKey = (import.meta.env.VITE_SUPABASE_ANON_KEY as string) || '';

  if (envUrl && envKey && !envUrl.includes('your-project-id')) {
    return {
      url: normalizeSupabaseUrl(envUrl),
      anonKey: envKey.trim(),
      isConfigured: true,
      source: 'env',
    };
  }

  return {
    url: normalizeSupabaseUrl(DEFAULT_SUPABASE_URL),
    anonKey: DEFAULT_SUPABASE_ANON_KEY,
    isConfigured: true,
    source: 'default',
  };
}

export function saveCustomSupabaseConfig(url: string, key: string) {
  if (url && key) {
    localStorage.setItem(SUPABASE_URL_KEY, normalizeSupabaseUrl(url));
    localStorage.setItem(SUPABASE_KEY_KEY, key.trim());
  } else {
    localStorage.removeItem(SUPABASE_URL_KEY);
    localStorage.removeItem(SUPABASE_KEY_KEY);
  }
  supabaseClientInstance = null; // reset client instance
}

let supabaseClientInstance: SupabaseClient | null = null;

export function getSupabaseClient(): SupabaseClient | null {
  if (supabaseClientInstance) {
    return supabaseClientInstance;
  }

  const config = getSupabaseConfig();
  if (!config.isConfigured || !config.url || !config.anonKey) {
    return null;
  }

  try {
    supabaseClientInstance = createClient(config.url, config.anonKey, {
      auth: {
        persistSession: false,
      },
    });
    return supabaseClientInstance;
  } catch (err) {
    console.error('Failed to initialize Supabase client:', err);
    return null;
  }
}

// Connection test
export async function testSupabaseConnection(): Promise<{
  success: boolean;
  message: string;
  userCount?: number;
}> {
  const client = getSupabaseClient();
  if (!client) {
    return {
      success: false,
      message: 'Supabase URL and Anon Key are not configured.',
    };
  }

  try {
    const { count, error } = await client
      .from('users')
      .select('*', { count: 'exact', head: true });

    if (error) {
      return {
        success: false,
        message: `Supabase error: ${error.message}`,
      };
    }

    return {
      success: true,
      message: `Connected to Supabase PostgreSQL successfully! (${count ?? 0} user records found)`,
      userCount: count ?? 0,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      success: false,
      message: `Connection test failed: ${msg}`,
    };
  }
}

// Fetch users
export async function fetchUsersFromSupabase(): Promise<User[] | null> {
  const client = getSupabaseClient();
  if (!client) return null;

  try {
    const { data, error } = await client
      .from('users')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      console.warn('Error fetching users from Supabase:', error.message);
      return null;
    }

    return (data as User[]) || [];
  } catch {
    return null;
  }
}

// Insert user
export async function insertUserToSupabase(user: Omit<User, 'id'>): Promise<User | null> {
  const client = getSupabaseClient();
  if (!client) return null;

  try {
    const { data, error } = await client
      .from('users')
      .insert([user])
      .select()
      .single();

    if (error) {
      console.warn('Error inserting user to Supabase:', error.message);
      return null;
    }

    return data as User;
  } catch {
    return null;
  }
}

// Update OTP
export async function updateUserOtpInSupabase(
  userId: number,
  otpCode: string,
  expiresAt: string
): Promise<boolean> {
  const client = getSupabaseClient();
  if (!client) return false;

  try {
    const { error } = await client
      .from('users')
      .update({
        otp_code: otpCode,
        otp_expires_at: expiresAt,
      })
      .eq('id', userId);

    return !error;
  } catch {
    return false;
  }
}

// Clear OTP & Verify email
export async function verifyUserInSupabase(userId: number): Promise<boolean> {
  const client = getSupabaseClient();
  if (!client) return false;

  try {
    const { error } = await client
      .from('users')
      .update({
        otp_code: null,
        otp_expires_at: null,
        email_verified: true,
      })
      .eq('id', userId);

    return !error;
  } catch {
    return false;
  }
}

// Fetch backup history
export async function fetchBackupHistoryFromSupabase(): Promise<BackupHistoryEntry[] | null> {
  const client = getSupabaseClient();
  if (!client) return null;

  try {
    const { data, error } = await client
      .from('infosec_backup_history')
      .select('*')
      .order('started_at', { ascending: false });

    if (error) {
      console.warn('Error fetching backup history from Supabase:', error.message);
      return null;
    }

    return (data as BackupHistoryEntry[]) || [];
  } catch {
    return null;
  }
}

// Insert backup entry
export async function insertBackupToSupabase(
  entry: Omit<BackupHistoryEntry, 'id'>
): Promise<BackupHistoryEntry | null> {
  const client = getSupabaseClient();
  if (!client) return null;

  try {
    const { data, error } = await client
      .from('infosec_backup_history')
      .insert([entry])
      .select()
      .single();

    if (error) {
      console.warn('Error inserting backup history to Supabase:', error.message);
      return null;
    }

    return data as BackupHistoryEntry;
  } catch {
    return null;
  }
}
