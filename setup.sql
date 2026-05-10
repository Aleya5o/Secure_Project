
--  Run this script once before starting the application:
--    mysql -u root -p < setup.sql
--
--  Security measures applied:
--  - Passwords stored as BCrypt hashes (never plaintext)
--  - account_locked flag supports brute-force lockout
--  - failed_attempts counter supports lockout policy
--  - role column supports Role-Based Access Control (RBAC)
-- ============================================================

CREATE DATABASE IF NOT EXISTS osis_db;
USE osis_db;

-- ── Users table 
CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(30)  NOT NULL UNIQUE,
    password_hash   VARCHAR(60)  NOT NULL,           -- BCrypt hash (always 60 chars)
    role            ENUM('student','instructor','admin') NOT NULL DEFAULT 'student',
    account_locked  BOOLEAN      NOT NULL DEFAULT FALSE,
    failed_attempts INT          NOT NULL DEFAULT 0,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);


--  Passwords below are BCrypt hashes of the plaintext passwords shown in the
--  To generate a hash in Java:
--      String hash = BCrypt.hashpw("Password123", BCrypt.gensalt());
--
--  Plaintext passwords used here (for testing only):
--      student1  - password: Password@123
--      professor2    - password: Password@123
--      admin    - password: Password@123

INSERT INTO users (username, password_hash, role) VALUES
(
    'student1',
    '$2a$10$LdR036z2TagKv75xH5JcsudNAXHTBfZT4eBPPo6HSwiSn8zDEhuYm',
    'student'
),
(
    'professor1',
    '$2a$10$LdR036z2TagKv75xH5JcsudNAXHTBfZT4eBPPo6HSwiSn8zDEhuYm',
    'instructor'
),
(
    'admin',
    '$2a$10$LdR036z2TagKv75xH5JcsudNAXHTBfZT4eBPPo6HSwiSn8zDEhuYm',
    'admin'
);

-- ── Verify setup ─
SELECT id, username, role, account_locked, failed_attempts, created_at
FROM users;

