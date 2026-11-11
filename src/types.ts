export interface User {
  id: number;
  name: string;
  email: string;
  password_hash: string;
  password_salt: string;
  role: 'user' | 'admin';
  otp_code?: string | null;
  otp_expires_at?: string | null;
  email_verified: boolean;
  created_at: string;
}

export interface BackupHistoryEntry {
  id: number;
  operation: 'backup' | 'restore';
  drive_file_id: string;
  file_name: string;
  size_bytes: number;
  sha256: string;
  status: 'success' | 'failed' | 'expired';
  message: string;
  requested_by?: number;
  started_at: string;
  completed_at?: string;
  snapshot_data?: string; // JSON string of database snapshot for restored content
}

export interface DriveConfig {
  connected: boolean;
  connectedEmail?: string;
  folderName: string;
  folderId?: string;
  lastConnectedAt?: string;
}

export interface SelfTestResult {
  filename: string;
  size_bytes: number;
  project_files: number;
  database_dump_bytes: number;
  verified: boolean;
  checked_at: string;
}
