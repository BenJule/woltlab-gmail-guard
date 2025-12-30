<?php
namespace wcf\data\user;

use wcf\system\WCF;
use wcf\system\exception\UserInputException;

/**
 * Enhanced email validator with comprehensive anti-spam features.
 *
 * @author  Custom Development
 * @license Apache License 2.0
 * @version 2.0.0
 */
class GmailValidator {

    /**
     * Comprehensive email validation with all features
     */
    public static function validateEmail(string $email, string $ipAddress, string $username = '', array $formData = []): array {
        $result = [
            'valid' => true,
            'suspicious' => false,
            'blocked' => false,
            'score' => 0,
            'reasons' => [],
            'requiresVerification' => false,
            'details' => []
        ];

        if (!GMAIL_GUARD_ENABLED) {
            return $result;
        }

        DisposableEmailChecker::loadCustomDomains();

        // STEP 1: Whitelist check (always allow)
        if (WhitelistBlacklistManager::isWhitelisted($email)) {
            $result['details']['whitelisted'] = true;
            return $result;
        }

        // STEP 2: Blacklist check (always block)
        if (WhitelistBlacklistManager::isBlacklisted($email)) {
            $result['blocked'] = true;
            $result['valid'] = false;
            $result['score'] = 100;
            $result['reasons'][] = 'blacklisted';
            return $result;
        }

        // STEP 3: IP ban check
        if (RateLimiter::isBanned($ipAddress)) {
            $result['blocked'] = true;
            $result['valid'] = false;
            $result['reasons'][] = 'ip_banned';
            $timeRemaining = RateLimiter::getBanTimeRemaining($ipAddress);
            $result['details']['ban_time_remaining'] = $timeRemaining;
            return $result;
        }

        // STEP 4: Rate limiting check
        if (RateLimiter::isRateLimited($ipAddress)) {
            $result['blocked'] = true;
            $result['valid'] = false;
            $result['score'] = 100;
            $result['reasons'][] = 'rate_limited';
            return $result;
        }

        $totalScore = 0;

        // STEP 5: Gmail-specific pattern checks
        if (self::isGmailAddress($email)) {
            if (GMAIL_GUARD_PATTERN_CHECK) {
                $patternResult = self::checkPatterns($email);
                $totalScore += $patternResult['score'];
                $result['reasons'] = array_merge($result['reasons'], $patternResult['reasons']);
                $result['details']['pattern_check'] = $patternResult;
            }

            // EmailRep.io API check
            if (GMAIL_GUARD_API_CHECK && !empty(GMAIL_GUARD_API_KEY)) {
                $apiResult = self::checkEmailReputation($email);
                $totalScore += $apiResult['score'];
                $result['reasons'] = array_merge($result['reasons'], $apiResult['reasons']);
                $result['details']['emailrep_check'] = $apiResult;
            }
        }

        // STEP 6: Disposable email check (all email providers)
        if (GMAIL_GUARD_DISPOSABLE_CHECK_ENABLED) {
            $disposableResult = DisposableEmailChecker::isDisposable($email);
            if ($disposableResult['isDisposable']) {
                $totalScore += $disposableResult['score'];
                $result['reasons'][] = 'disposable_email';
                $result['details']['disposable_check'] = $disposableResult;
            }

            // Also check via API
            if (GMAIL_GUARD_DISPOSABLE_API_ENABLED) {
                $apiDisposable = DisposableEmailChecker::checkViaAPI($email);
                if ($apiDisposable['isDisposable']) {
                    $totalScore += ($apiDisposable['score'] / 2); // Half weight to avoid double counting
                    $result['reasons'][] = 'disposable_email_api';
                }
            }
        }

        // STEP 7: StopForumSpam check
        if (GMAIL_GUARD_SFS_ENABLED) {
            $sfsResult = StopForumSpamChecker::check($email, $ipAddress, $username);
            if ($sfsResult['spam']) {
                $totalScore += $sfsResult['score'];
                $result['reasons'] = array_merge($result['reasons'], $sfsResult['reasons']);
                $result['details']['stopforumspam_check'] = $sfsResult;
            }
        }

        // STEP 8: Browser/Bot validation
        if (!empty($formData)) {
            // Honeypot check
            if (isset($formData['honeypot']) && GMAIL_GUARD_HONEYPOT_ENABLED) {
                $honeypotResult = AntiBotValidator::validateHoneypot($formData['honeypot']);
                if ($honeypotResult['isBot']) {
                    $totalScore += $honeypotResult['score'];
                    $result['reasons'][] = $honeypotResult['reason'];
                    $result['details']['honeypot_check'] = $honeypotResult;
                }
            }

            // Timing check
            if (isset($formData['timing_token']) && GMAIL_GUARD_TIMING_CHECK_ENABLED) {
                $formLoadTime = AntiBotValidator::decodeTimingToken($formData['timing_token']);
                if ($formLoadTime > 0) {
                    $timingResult = AntiBotValidator::validateTiming($formLoadTime);
                    if ($timingResult['isBot'] || $timingResult['score'] > 0) {
                        $totalScore += $timingResult['score'];
                        $result['reasons'][] = $timingResult['reason'];
                        $result['details']['timing_check'] = $timingResult;
                    }
                }
            }

            // Browser fingerprinting
            if (GMAIL_GUARD_BROWSER_CHECK_ENABLED) {
                $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
                $headers = AntiBotValidator::getBrowserHeaders();
                $browserResult = AntiBotValidator::validateBrowser($userAgent, $headers);
                if ($browserResult['isBot'] || $browserResult['score'] > 0) {
                    $totalScore += $browserResult['score'];
                    $result['reasons'] = array_merge($result['reasons'], $browserResult['reasons']);
                    $result['details']['browser_check'] = $browserResult;
                }
            }
        }

        // STEP 9: Time restriction check
        if (GMAIL_GUARD_TIME_RESTRICTION_ENABLED) {
            $timeCheck = AntiBotValidator::isTimeAllowed();
            if (!$timeCheck['allowed']) {
                $totalScore += 50;
                $result['reasons'][] = $timeCheck['reason'];
                $result['details']['time_restriction'] = $timeCheck;
            }
        }

        // STEP 10: Evaluate final score
        $result['score'] = $totalScore;
        $threshold = GMAIL_GUARD_THRESHOLD;

        if ($totalScore >= $threshold) {
            $result['suspicious'] = true;
            $result['requiresVerification'] = true;

            // Check action type
            $action = GMAIL_GUARD_ACTION;
            if ($action === 'block') {
                $result['blocked'] = true;
                $result['valid'] = false;
            }

            // Record suspicious attempt and check for auto-ban
            RateLimiter::recordAttempt($ipAddress, $email, true);
            RateLimiter::checkAndAutoBan($ipAddress);
        } else {
            // Record normal attempt
            RateLimiter::recordAttempt($ipAddress, $email, false);
        }

        return $result;
    }

    /**
     * Check if email is a Gmail address
     */
    public static function isGmailAddress(string $email): bool {
        return (bool)preg_match('/@gmail\.com$/i', $email);
    }

    /**
     * Legacy method for backward compatibility
     */
    public static function validateGmailAddress(string $email): array {
        $ipAddress = WCF::getSession()->ipAddress;
        $fullResult = self::validateEmail($email, $ipAddress);

        return [
            'suspicious' => $fullResult['suspicious'],
            'score' => $fullResult['score'],
            'reasons' => $fullResult['reasons'],
            'requiresVerification' => $fullResult['requiresVerification']
        ];
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

        // Pattern 2: Random character sequences
        if (preg_match('/^[a-z0-9]{10,}$/i', $localPart) &&
            !preg_match('/[aeiou]{2}/i', $localPart)) {
            $score += 25;
            $reasons[] = 'random_character_sequence';
        }

        // Pattern 3: Too many dots
        $dotCount = substr_count($localPart, '.');
        if ($dotCount > 3) {
            $score += 20;
            $reasons[] = 'excessive_dots';
        }

        // Pattern 4: Very short addresses
        if (strlen(str_replace('.', '', $localPart)) < 4) {
            $score += 15;
            $reasons[] = 'very_short_address';
        }

        // Pattern 5: Repeating patterns
        if (preg_match('/(.{3,})\1{2,}/', $localPart)) {
            $score += 20;
            $reasons[] = 'repeating_pattern';
        }

        // Pattern 6: Common spam patterns
        $spamPatterns = ['test', 'temp', 'fake', 'spam', 'random', 'xxx', '123456', 'admin', 'webmaster'];
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
                    'User-Agent: WoltLab-GmailGuard/2.0'
                ]
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200 && $response) {
                $data = json_decode($response, true);

                if (isset($data['reputation'])) {
                    $reputation = strtolower($data['reputation']);

                    if ($reputation === 'high' || $reputation === 'suspicious') {
                        $score += 50;
                        $reasons[] = 'api_high_risk';
                    } elseif ($reputation === 'medium' || $reputation === 'low') {
                        $score += 25;
                        $reasons[] = 'api_medium_risk';
                    }
                }

                if (isset($data['details']['suspicious']) && $data['details']['suspicious'] === true) {
                    $score += 30;
                    $reasons[] = 'api_suspicious_flag';
                }

                if (isset($data['details']['disposable']) && $data['details']['disposable'] === true) {
                    $score += 40;
                    $reasons[] = 'api_disposable';
                }

                if (isset($data['details']['spam']) && $data['details']['spam'] === true) {
                    $score += 50;
                    $reasons[] = 'api_spam';
                }
            }
        } catch (\Exception $e) {
            if (GMAIL_GUARD_LOG_ERRORS) {
                error_log('GmailGuard API Error: ' . $e->getMessage());
            }
        }

        return ['score' => $score, 'reasons' => $reasons];
    }

    /**
     * Get human-readable reason for suspicious detection
     */
    public static function getSuspiciousReason(array $reasons): string {
        if (empty($reasons)) {
            return WCF::getLanguage()->get('wcf.user.gmail.suspicious.generic');
        }

        $primaryReason = $reasons[0];
        return WCF::getLanguage()->getDynamicVariable('wcf.user.gmail.suspicious.' . $primaryReason);
    }
}
