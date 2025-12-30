<?php
namespace wcf\data\user;

use wcf\system\WCF;
use wcf\system\exception\UserInputException;

/**
 * Validates Gmail addresses using API reputation check and pattern analysis.
 *
 * @author  Custom Development
 * @license Apache License 2.0
 */
class GmailValidator {

    /**
     * Check if email is a Gmail address
     */
    public static function isGmailAddress(string $email): bool {
        return (bool)preg_match('/@gmail\.com$/i', $email);
    }

    /**
     * Validate Gmail address using combined methods
     * Returns array with validation result and score
     */
    public static function validateGmailAddress(string $email): array {
        $result = [
            'suspicious' => false,
            'score' => 0,
            'reasons' => [],
            'requiresVerification' => false
        ];

        // Skip if Gmail validation is disabled
        if (!GMAIL_GUARD_ENABLED) {
            return $result;
        }

        // Only check Gmail addresses
        if (!self::isGmailAddress($email)) {
            return $result;
        }

        $suspiciousScore = 0;

        // Method 1: Pattern-based detection
        if (GMAIL_GUARD_PATTERN_CHECK) {
            $patternScore = self::checkPatterns($email);
            $suspiciousScore += $patternScore['score'];
            if (!empty($patternScore['reasons'])) {
                $result['reasons'] = array_merge($result['reasons'], $patternScore['reasons']);
            }
        }

        // Method 2: Email Reputation API
        if (GMAIL_GUARD_API_CHECK && !empty(GMAIL_GUARD_API_KEY)) {
            $apiScore = self::checkEmailReputation($email);
            $suspiciousScore += $apiScore['score'];
            if (!empty($apiScore['reasons'])) {
                $result['reasons'] = array_merge($result['reasons'], $apiScore['reasons']);
            }
        }

        // Determine if suspicious based on threshold
        $threshold = GMAIL_GUARD_THRESHOLD;
        $result['score'] = $suspiciousScore;

        if ($suspiciousScore >= $threshold) {
            $result['suspicious'] = true;
            $result['requiresVerification'] = true;
        }

        return $result;
    }

    /**
     * Pattern-based analysis for suspicious Gmail addresses
     */
    private static function checkPatterns(string $email): array {
        $score = 0;
        $reasons = [];
        $localPart = explode('@', $email)[0];

        // Pattern 1: Too many random numbers (>6 consecutive digits)
        if (preg_match('/\d{7,}/', $localPart)) {
            $score += 30;
            $reasons[] = 'many_consecutive_numbers';
        }

        // Pattern 2: Random character sequences (e.g., kjhf8sd7f)
        if (preg_match('/^[a-z0-9]{10,}$/i', $localPart) &&
            !preg_match('/[aeiou]{2}/i', $localPart)) {
            $score += 25;
            $reasons[] = 'random_character_sequence';
        }

        // Pattern 3: Too many dots (Gmail trick for multiple registrations)
        $dotCount = substr_count($localPart, '.');
        if ($dotCount > 3) {
            $score += 20;
            $reasons[] = 'excessive_dots';
        }

        // Pattern 4: Very short addresses (< 4 characters) are often bots
        if (strlen(str_replace('.', '', $localPart)) < 4) {
            $score += 15;
            $reasons[] = 'very_short_address';
        }

        // Pattern 5: Repeating patterns (e.g., abcabc123123)
        if (preg_match('/(.{3,})\1{2,}/', $localPart)) {
            $score += 20;
            $reasons[] = 'repeating_pattern';
        }

        // Pattern 6: Common spam patterns
        $spamPatterns = ['test', 'temp', 'fake', 'spam', 'random', 'xxx', '123456'];
        foreach ($spamPatterns as $pattern) {
            if (stripos($localPart, $pattern) !== false) {
                $score += 25;
                $reasons[] = 'spam_keyword';
                break;
            }
        }

        return ['score' => $score, 'reasons' => $reasons];
    }

    /**
     * Check email reputation using EmailRep.io API
     */
    private static function checkEmailReputation(string $email): array {
        $score = 0;
        $reasons = [];

        try {
            $apiKey = GMAIL_GUARD_API_KEY;
            $apiUrl = "https://emailrep.io/" . urlencode($email);

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $apiUrl,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 5,
                CURLOPT_HTTPHEADER => [
                    'Key: ' . $apiKey,
                    'User-Agent: WoltLab-GmailGuard/1.0'
                ]
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200 && $response) {
                $data = json_decode($response, true);

                if (isset($data['reputation'])) {
                    $reputation = strtolower($data['reputation']);

                    // High risk reputation
                    if ($reputation === 'high' || $reputation === 'suspicious') {
                        $score += 50;
                        $reasons[] = 'api_high_risk';
                    }
                    // Medium risk
                    elseif ($reputation === 'medium' || $reputation === 'low') {
                        $score += 25;
                        $reasons[] = 'api_medium_risk';
                    }
                }

                // Check suspicious flag
                if (isset($data['details']['suspicious']) && $data['details']['suspicious'] === true) {
                    $score += 30;
                    $reasons[] = 'api_suspicious_flag';
                }

                // Check if disposable email
                if (isset($data['details']['disposable']) && $data['details']['disposable'] === true) {
                    $score += 40;
                    $reasons[] = 'api_disposable';
                }

                // Check spam flag
                if (isset($data['details']['spam']) && $data['details']['spam'] === true) {
                    $score += 50;
                    $reasons[] = 'api_spam';
                }
            }
        } catch (\Exception $e) {
            // API error - log but don't block registration
            if (GMAIL_GUARD_LOG_ERRORS) {
                error_log('GmailGuard API Error: ' . $e->getMessage());
            }
        }

        return ['score' => $score, 'reasons' => $reasons];
    }

    /**
     * Apply additional verification requirements
     */
    public static function requiresAdditionalVerification(string $email): bool {
        $validation = self::validateGmailAddress($email);
        return $validation['requiresVerification'];
    }

    /**
     * Get human-readable reason for suspicious detection
     */
    public static function getSuspiciousReason(array $reasons): string {
        if (empty($reasons)) {
            return WCF::getLanguage()->get('wcf.user.gmail.suspicious.generic');
        }

        // Return first reason as primary
        $primaryReason = $reasons[0];
        return WCF::getLanguage()->getDynamicVariable('wcf.user.gmail.suspicious.' . $primaryReason);
    }
}
