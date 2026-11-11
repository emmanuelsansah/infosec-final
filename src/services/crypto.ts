/**
 * InfoSec Cryptographic Module
 * Matches PHP implementation:
 * - Salt: bin2hex(random_bytes(16))
 * - OTP: 6-digit random code (100000 - 999999) with 300 second (5 min) expiry
 * - Pepper: Site-wide secret pepper key
 * - Password Hash: hash_hmac('sha256', password, APP_PEPPER . salt)
 * - Archive Checksum: SHA-256 digest
 */

export const APP_PEPPER = 'infosec_secure_app_pepper_2026_x90f!';
export const OTP_EXPIRY_SECONDS = 300; // 5 minutes

export function generateSalt(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function generateOtp(): string {
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  const code = (array[0] % 900000) + 100000;
  return code.toString();
}

export async function hashPasswordWithPepper(
  password: string,
  salt: string,
  pepper = APP_PEPPER
): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(pepper + salt);
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(password));
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function verifyPassword(
  password: string,
  storedHash: string,
  salt: string,
  pepper = APP_PEPPER
): Promise<boolean> {
  const computedHash = await hashPasswordWithPepper(password, salt, pepper);
  return computedHash.toLowerCase() === storedHash.toLowerCase();
}

export async function calculateSha256(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(content));
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function evaluatePasswordStrength(password: string): {
  score: number;
  label: 'Weak' | 'Medium' | 'Strong';
  color: string;
} {
  if (!password) {
    return { score: 0, label: 'Weak', color: 'var(--muted)' };
  }
  let score = 0;
  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 2) {
    return { score, label: 'Weak', color: 'var(--danger)' };
  } else if (score >= 3 && score <= 4) {
    return { score, label: 'Medium', color: '#d97706' };
  } else {
    return { score, label: 'Strong', color: 'var(--success)' };
  }
}
