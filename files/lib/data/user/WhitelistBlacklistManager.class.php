<?php
namespace wcf\data\user;

use wcf\system\WCF;

/**
 * Manages whitelist and blacklist for email addresses and domains.
 *
 * @author  Custom Development
 * @license Apache License 2.0
 */
class WhitelistBlacklistManager {

    /**
     * Check if email is whitelisted
     */
    public static function isWhitelisted(string $email): bool {
        if (!GMAIL_GUARD_WHITELIST_ENABLED) {
            return false;
        }

        $email = strtolower(trim($email));
        $domain = self::getDomain($email);

        // Check exact email match
        if (self::isInList($email, 'whitelist')) {
            return true;
        }

        // Check domain match
        if (self::isInList($domain, 'whitelist')) {
            return true;
        }

        return false;
    }

    /**
     * Check if email is blacklisted
     */
    public static function isBlacklisted(string $email): bool {
        if (!GMAIL_GUARD_BLACKLIST_ENABLED) {
            return false;
        }

        $email = strtolower(trim($email));
        $domain = self::getDomain($email);

        // Check exact email match
        if (self::isInList($email, 'blacklist')) {
            return true;
        }

        // Check domain match
        if (self::isInList($domain, 'blacklist')) {
            return true;
        }

        return false;
    }

    /**
     * Check if value is in list
     */
    private static function isInList(string $value, string $listType): bool {
        $optionName = 'gmail_guard_' . $listType;
        $list = defined(strtoupper($optionName)) ? constant(strtoupper($optionName)) : '';

        if (empty($list)) {
            return false;
        }

        // Split by newline and check each entry
        $entries = array_map('trim', explode("\n", $list));
        $entries = array_map('strtolower', $entries);
        $entries = array_filter($entries); // Remove empty lines

        return in_array($value, $entries);
    }

    /**
     * Get domain from email
     */
    private static function getDomain(string $email): string {
        $parts = explode('@', $email);
        return isset($parts[1]) ? $parts[1] : '';
    }

    /**
     * Add email to whitelist (for future admin panel)
     */
    public static function addToWhitelist(string $email): bool {
        return self::addToList($email, 'whitelist');
    }

    /**
     * Add email to blacklist (for future admin panel)
     */
    public static function addToBlacklist(string $email): bool {
        return self::addToList($email, 'blacklist');
    }

    /**
     * Add entry to list
     */
    private static function addToList(string $value, string $listType): bool {
        $optionName = 'gmail_guard_' . $listType;
        $currentList = defined(strtoupper($optionName)) ? constant(strtoupper($optionName)) : '';

        $entries = array_filter(array_map('trim', explode("\n", $currentList)));
        $value = strtolower(trim($value));

        if (in_array($value, $entries)) {
            return false; // Already in list
        }

        $entries[] = $value;
        $newList = implode("\n", $entries);

        // Update option in database
        $sql = "UPDATE wcf" . WCF_N . "_option
                SET optionValue = ?
                WHERE optionName = ?";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([$newList, $optionName]);

        return true;
    }

    /**
     * Remove from list
     */
    public static function removeFromList(string $value, string $listType): bool {
        $optionName = 'gmail_guard_' . $listType;
        $currentList = defined(strtoupper($optionName)) ? constant(strtoupper($optionName)) : '';

        $entries = array_filter(array_map('trim', explode("\n", $currentList)));
        $value = strtolower(trim($value));

        $entries = array_diff($entries, [$value]);
        $newList = implode("\n", $entries);

        // Update option in database
        $sql = "UPDATE wcf" . WCF_N . "_option
                SET optionValue = ?
                WHERE optionName = ?";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([$newList, $optionName]);

        return true;
    }
}
