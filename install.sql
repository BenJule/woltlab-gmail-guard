-- Gmail Guard v2.0.0 Database Schema
-- Enhanced tables for comprehensive anti-spam protection

-- Main log table (enhanced)
CREATE TABLE IF NOT EXISTS wcf1_gmail_guard_log (
    logID INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    score INT(3) NOT NULL,
    reasons TEXT,
    ipAddress VARCHAR(45) NOT NULL,
    userAgent TEXT,
    details TEXT,
    time INT(10) NOT NULL,
    INDEX (email),
    INDEX (ipAddress),
    INDEX (time),
    INDEX (score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Rate limiting table
CREATE TABLE IF NOT EXISTS wcf1_gmail_guard_rate_limit (
    attemptID INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ipAddress VARCHAR(45) NOT NULL,
    email VARCHAR(255),
    suspicious TINYINT(1) DEFAULT 0,
    timestamp INT(10) NOT NULL,
    INDEX (ipAddress),
    INDEX (timestamp),
    INDEX (suspicious)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- IP ban table
CREATE TABLE IF NOT EXISTS wcf1_gmail_guard_ip_ban (
    banID INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ipAddress VARCHAR(45) NOT NULL UNIQUE,
    bannedAt INT(10) NOT NULL,
    expiresAt INT(10) NOT NULL,
    banCount INT(5) DEFAULT 1,
    reason TEXT,
    INDEX (ipAddress),
    INDEX (expiresAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Statistics table (optional, for dashboard)
CREATE TABLE IF NOT EXISTS wcf1_gmail_guard_stats (
    statID INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    date DATE NOT NULL,
    totalAttempts INT(10) DEFAULT 0,
    suspiciousAttempts INT(10) DEFAULT 0,
    blockedAttempts INT(10) DEFAULT 0,
    uniqueIPs INT(10) DEFAULT 0,
    avgScore DECIMAL(5,2) DEFAULT 0.00,
    UNIQUE KEY date_unique (date),
    INDEX (date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
