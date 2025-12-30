<?php
namespace wcf\data\user;

use wcf\system\WCF;
use wcf\util\UserUtil;

/**
 * Anti-bot validation using honeypot, timing, and browser fingerprinting.
 *
 * @author  Custom Development
 * @license Apache License 2.0
 */
class AntiBotValidator {

    /**
     * Validate honeypot field
     */
    public static function validateHoneypot(string $honeypotValue): array {
        $result = [
            'isBot' => false,
            'score' => 0,
            'reason' => ''
        ];

        if (!GMAIL_GUARD_HONEYPOT_ENABLED) {
            return $result;
        }

        // Honeypot field should be empty
        if (!empty($honeypotValue)) {
            $result['isBot'] = true;
            $result['score'] = 100; // Definite bot
            $result['reason'] = 'honeypot_filled';
        }

        return $result;
    }

    /**
     * Validate form submission timing
     */
    public static function validateTiming(int $formLoadTime): array {
        $result = [
            'isBot' => false,
            'score' => 0,
            'reason' => ''
        ];

        if (!GMAIL_GUARD_TIMING_CHECK_ENABLED) {
            return $result;
        }

        $currentTime = TIME_NOW;
        $timeTaken = $currentTime - $formLoadTime;

        // Too fast (< 3 seconds = bot)
        $minTime = GMAIL_GUARD_MIN_FORM_TIME;
        if ($timeTaken < $minTime) {
            $result['isBot'] = true;
            $result['score'] = 80;
            $result['reason'] = 'form_too_fast';
        }

        // Suspiciously fast (< 10 seconds)
        elseif ($timeTaken < 10) {
            $result['score'] = 40;
            $result['reason'] = 'form_suspiciously_fast';
        }

        // Too slow (> 1 hour = possible automated script)
        $maxTime = GMAIL_GUARD_MAX_FORM_TIME;
        if ($timeTaken > $maxTime) {
            $result['score'] = 30;
            $result['reason'] = 'form_too_slow';
        }

        return $result;
    }

    /**
     * Validate browser fingerprint
     */
    public static function validateBrowser(string $userAgent, array $headers = []): array {
        $result = [
            'isBot' => false,
            'score' => 0,
            'reasons' => []
        ];

        if (!GMAIL_GUARD_BROWSER_CHECK_ENABLED) {
            return $result;
        }

        // Check for empty user agent
        if (empty($userAgent)) {
            $result['isBot'] = true;
            $result['score'] += 60;
            $result['reasons'][] = 'no_user_agent';
        }

        // Check for bot keywords in user agent
        $botKeywords = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 'java'];
        foreach ($botKeywords as $keyword) {
            if (stripos($userAgent, $keyword) !== false) {
                $result['isBot'] = true;
                $result['score'] += 70;
                $result['reasons'][] = 'bot_user_agent';
                break;
            }
        }

        // Check for headless browsers
        $headlessKeywords = ['headless', 'phantomjs', 'nightmare', 'puppeteer', 'selenium'];
        foreach ($headlessKeywords as $keyword) {
            if (stripos($userAgent, $keyword) !== false) {
                $result['isBot'] = true;
                $result['score'] += 80;
                $result['reasons'][] = 'headless_browser';
                break;
            }
        }

        // Check for missing common headers
        if (!empty($headers)) {
            $requiredHeaders = ['accept', 'accept-language'];
            foreach ($requiredHeaders as $header) {
                if (!isset($headers[$header]) || empty($headers[$header])) {
                    $result['score'] += 20;
                    $result['reasons'][] = 'missing_headers';
                    break;
                }
            }

            // Check for suspicious header patterns
            if (isset($headers['accept']) && $headers['accept'] === '*/*') {
                $result['score'] += 15;
                $result['reasons'][] = 'generic_accept_header';
            }
        }

        // Check user agent browser/OS consistency
        $hasWindows = stripos($userAgent, 'Windows') !== false;
        $hasMac = stripos($userAgent, 'Mac') !== false;
        $hasLinux = stripos($userAgent, 'Linux') !== false;
        $hasAndroid = stripos($userAgent, 'Android') !== false;
        $hasiOS = stripos($userAgent, 'iPhone') !== false || stripos($userAgent, 'iPad') !== false;

        $hasChrome = stripos($userAgent, 'Chrome') !== false;
        $hasFirefox = stripos($userAgent, 'Firefox') !== false;
        $hasSafari = stripos($userAgent, 'Safari') !== false && !$hasChrome;
        $hasEdge = stripos($userAgent, 'Edg') !== false;

        // No OS or browser detected = suspicious
        if (!$hasWindows && !$hasMac && !$hasLinux && !$hasAndroid && !$hasiOS) {
            $result['score'] += 30;
            $result['reasons'][] = 'unknown_os';
        }

        if (!$hasChrome && !$hasFirefox && !$hasSafari && !$hasEdge) {
            $result['score'] += 25;
            $result['reasons'][] = 'unknown_browser';
        }

        return $result;
    }

    /**
     * Check if registration time is allowed
     */
    public static function isTimeAllowed(): array {
        $result = [
            'allowed' => true,
            'reason' => ''
        ];

        if (!GMAIL_GUARD_TIME_RESTRICTION_ENABLED) {
            return $result;
        }

        $currentHour = (int)date('G'); // 0-23
        $startHour = (int)GMAIL_GUARD_ALLOWED_START_HOUR;
        $endHour = (int)GMAIL_GUARD_ALLOWED_END_HOUR;

        // Check if current hour is within allowed range
        if ($startHour <= $endHour) {
            // Normal range (e.g., 8-20)
            if ($currentHour < $startHour || $currentHour >= $endHour) {
                $result['allowed'] = false;
                $result['reason'] = 'outside_allowed_hours';
            }
        } else {
            // Overnight range (e.g., 20-8)
            if ($currentHour < $startHour && $currentHour >= $endHour) {
                $result['allowed'] = false;
                $result['reason'] = 'outside_allowed_hours';
            }
        }

        return $result;
    }

    /**
     * Get honeypot field name (obfuscated)
     */
    public static function getHoneypotFieldName(): string {
        // Generate consistent but obfuscated field name
        return 'website_url'; // Common field name that bots often fill
    }

    /**
     * Generate form timestamp token
     */
    public static function generateTimingToken(): string {
        $data = TIME_NOW . '|' . WCF::getSession()->sessionID;
        return base64_encode($data);
    }

    /**
     * Decode timing token
     */
    public static function decodeTimingToken(string $token): int {
        try {
            $decoded = base64_decode($token);
            $parts = explode('|', $decoded);
            return isset($parts[0]) ? (int)$parts[0] : 0;
        } catch (\Exception $e) {
            return 0;
        }
    }

    /**
     * Get browser headers for fingerprinting
     */
    public static function getBrowserHeaders(): array {
        $headers = [];

        if (isset($_SERVER['HTTP_ACCEPT'])) {
            $headers['accept'] = $_SERVER['HTTP_ACCEPT'];
        }
        if (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $headers['accept-language'] = $_SERVER['HTTP_ACCEPT_LANGUAGE'];
        }
        if (isset($_SERVER['HTTP_ACCEPT_ENCODING'])) {
            $headers['accept-encoding'] = $_SERVER['HTTP_ACCEPT_ENCODING'];
        }
        if (isset($_SERVER['HTTP_DNT'])) {
            $headers['dnt'] = $_SERVER['HTTP_DNT'];
        }

        return $headers;
    }
}
