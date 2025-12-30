-- Optional: Database table for logging suspicious registration attempts
-- Only needed if you enable "Database Logging" in the ACP

CREATE TABLE IF NOT EXISTS wcf1_gmail_guard_log (
    logID INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    score INT(3) NOT NULL,
    reasons TEXT,
    ipAddress VARCHAR(45) NOT NULL,
    time INT(10) NOT NULL,
    INDEX (email),
    INDEX (time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
