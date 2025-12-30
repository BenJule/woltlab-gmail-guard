<?php
namespace wcf\data\user;

use wcf\system\WCF;

/**
 * Rate limiting for registration attempts by IP address.
 *
 * @author  Custom Development
 * @license Apache License 2.0
 */
class RateLimiter {

    /**
     * Check if IP has exceeded rate limit
     */
    public static function isRateLimited(string $ipAddress): bool {
        if (!GMAIL_GUARD_RATE_LIMIT_ENABLED) {
            return false;
        }

        $maxAttempts = GMAIL_GUARD_RATE_LIMIT_MAX;
        $timeWindow = GMAIL_GUARD_RATE_LIMIT_WINDOW * 60; // Convert minutes to seconds
        $currentTime = TIME_NOW;
        $windowStart = $currentTime - $timeWindow;

        // Count attempts in time window
        $sql = "SELECT COUNT(*) as attemptCount
                FROM wcf" . WCF_N . "_gmail_guard_rate_limit
                WHERE ipAddress = ?
                AND timestamp >= ?";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([$ipAddress, $windowStart]);
        $row = $statement->fetchArray();

        $attemptCount = $row['attemptCount'] ?? 0;

        return $attemptCount >= $maxAttempts;
    }

    /**
     * Record registration attempt
     */
    public static function recordAttempt(string $ipAddress, string $email = '', bool $suspicious = false): void {
        if (!GMAIL_GUARD_RATE_LIMIT_ENABLED) {
            return;
        }

        $sql = "INSERT INTO wcf" . WCF_N . "_gmail_guard_rate_limit
                (ipAddress, email, suspicious, timestamp)
                VALUES (?, ?, ?, ?)";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([
            $ipAddress,
            $email,
            $suspicious ? 1 : 0,
            TIME_NOW
        ]);

        // Cleanup old entries
        self::cleanup();
    }

    /**
     * Check if IP is temporarily banned
     */
    public static function isBanned(string $ipAddress): bool {
        if (!GMAIL_GUARD_AUTO_BAN_ENABLED) {
            return false;
        }

        $sql = "SELECT COUNT(*) as banCount
                FROM wcf" . WCF_N . "_gmail_guard_ip_ban
                WHERE ipAddress = ?
                AND expiresAt > ?";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([$ipAddress, TIME_NOW]);
        $row = $statement->fetchArray();

        return ($row['banCount'] ?? 0) > 0;
    }

    /**
     * Ban IP temporarily
     */
    public static function banIP(string $ipAddress, int $duration = null): void {
        if (!GMAIL_GUARD_AUTO_BAN_ENABLED) {
            return;
        }

        if ($duration === null) {
            $duration = GMAIL_GUARD_BAN_DURATION * 3600; // Convert hours to seconds
        }

        $expiresAt = TIME_NOW + $duration;

        // Check if already banned
        $sql = "SELECT banID FROM wcf" . WCF_N . "_gmail_guard_ip_ban
                WHERE ipAddress = ?
                AND expiresAt > ?";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([$ipAddress, TIME_NOW]);
        $row = $statement->fetchArray();

        if ($row) {
            // Update existing ban
            $sql = "UPDATE wcf" . WCF_N . "_gmail_guard_ip_ban
                    SET expiresAt = ?, banCount = banCount + 1
                    WHERE banID = ?";
            $statement = WCF::getDB()->prepareStatement($sql);
            $statement->execute([$expiresAt, $row['banID']]);
        } else {
            // Create new ban
            $sql = "INSERT INTO wcf" . WCF_N . "_gmail_guard_ip_ban
                    (ipAddress, bannedAt, expiresAt, banCount, reason)
                    VALUES (?, ?, ?, 1, ?)";
            $statement = WCF::getDB()->prepareStatement($sql);
            $statement->execute([
                $ipAddress,
                TIME_NOW,
                $expiresAt,
                'Automatic ban due to suspicious registration attempts'
            ]);
        }
    }

    /**
     * Check and auto-ban if threshold reached
     */
    public static function checkAndAutoBan(string $ipAddress): bool {
        if (!GMAIL_GUARD_AUTO_BAN_ENABLED) {
            return false;
        }

        $threshold = GMAIL_GUARD_AUTO_BAN_THRESHOLD;
        $timeWindow = GMAIL_GUARD_AUTO_BAN_WINDOW * 60; // Convert minutes to seconds
        $windowStart = TIME_NOW - $timeWindow;

        // Count suspicious attempts in time window
        $sql = "SELECT COUNT(*) as suspiciousCount
                FROM wcf" . WCF_N . "_gmail_guard_rate_limit
                WHERE ipAddress = ?
                AND suspicious = 1
                AND timestamp >= ?";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([$ipAddress, $windowStart]);
        $row = $statement->fetchArray();

        $suspiciousCount = $row['suspiciousCount'] ?? 0;

        if ($suspiciousCount >= $threshold) {
            self::banIP($ipAddress);
            return true;
        }

        return false;
    }

    /**
     * Get remaining time for banned IP
     */
    public static function getBanTimeRemaining(string $ipAddress): int {
        $sql = "SELECT expiresAt FROM wcf" . WCF_N . "_gmail_guard_ip_ban
                WHERE ipAddress = ?
                AND expiresAt > ?
                ORDER BY expiresAt DESC
                LIMIT 1";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([$ipAddress, TIME_NOW]);
        $row = $statement->fetchArray();

        if (!$row) {
            return 0;
        }

        return max(0, $row['expiresAt'] - TIME_NOW);
    }

    /**
     * Cleanup old rate limit entries
     */
    private static function cleanup(): void {
        $maxAge = GMAIL_GUARD_RATE_LIMIT_WINDOW * 60 * 24; // Keep 24x the window
        $cutoff = TIME_NOW - $maxAge;

        // Clean rate limit table
        $sql = "DELETE FROM wcf" . WCF_N . "_gmail_guard_rate_limit
                WHERE timestamp < ?";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([$cutoff]);

        // Clean expired bans
        $sql = "DELETE FROM wcf" . WCF_N . "_gmail_guard_ip_ban
                WHERE expiresAt < ?";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([$cutoff]);
    }
}
