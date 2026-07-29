-- Run this in phpMyAdmin (XAMPP) or via: mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS auth_system;
USE auth_system;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NULL,          -- NULL for Google-only accounts
  google_id VARCHAR(255) NULL UNIQUE,
  name VARCHAR(255) NULL,
  failed_login_attempts INT NOT NULL DEFAULT 0,
  lock_until DATETIME NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  refresh_token_hash VARCHAR(255) NOT NULL,  -- we never store the raw refresh token
  user_agent VARCHAR(500),
  ip_address VARCHAR(100),
  is_suspicious BOOLEAN DEFAULT FALSE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  revoked_at DATETIME NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255),
  ip_address VARCHAR(100),
  success BOOLEAN,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_login_attempts_email ON login_attempts(email, created_at);
CREATE INDEX idx_sessions_user ON sessions(user_id, revoked_at);
