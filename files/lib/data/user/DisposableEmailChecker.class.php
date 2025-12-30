<?php
namespace wcf\data\user;

/**
 * Detects disposable/temporary email addresses from various providers.
 *
 * @author  Custom Development
 * @license Apache License 2.0
 */
class DisposableEmailChecker {

    /**
     * List of known disposable email domains
     */
    private static $disposableDomains = [
        // Popular disposable email services
        '10minutemail.com', '10minutemail.net', '10minutemail.org',
        'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
        'mailinator.com', 'mailinator.net', 'mailinator2.com',
        'tempmail.com', 'temp-mail.org', 'temp-mail.io',
        'throwaway.email', 'trashmail.com', 'getnada.com',
        'maildrop.cc', 'mintemail.com', 'mytemp.email',
        'sharklasers.com', 'grr.la', 'yopmail.com', 'yopmail.net',
        'fakeinbox.com', 'spambog.com', 'deadaddress.com',
        'mailcatch.com', 'emailondeck.com', 'emailfake.com',
        'dispostable.com', 'ThrowAwayMail.com', 'fake-mail.com',
        'mohmal.com', 'mailnesia.com', 'mytrashmail.com',
        'tempr.email', 'throwam.com', 'devnullmail.com',
        'emailsensei.com', 'mailexpire.com', 'tempemail.net',
        'gmailnator.com', 'emailtemporanea.com', 'emailtemporanea.net',
        'ephemail.net', 'filzmail.com', 'getairmail.com',
        'harakirimail.com', 'jetable.org', 'klzlk.com',
        'mailforspam.com', 'mailtothis.com', 'mt2014.com',
        'noclickemail.com', 'nospam.ze.tc', 'objectmail.com',
        'pookmail.com', 'proxymail.eu', 'sogetthis.com',
        'spambox.us', 'spamfree24.com', 'spamgourmet.com',
        'spamspot.com', 'supergreatmail.com', 'teleworm.com',
        'tmailinator.com', 'wasteland.rfc822.org', 'wegwerfmail.de',
        'wegwerfmail.net', 'wegwerfmail.org', 'wh4f.org',
        'zoemail.org', 'trbvm.com', 'correotemporal.org'
    ];

    /**
     * Check if email domain is disposable
     */
    public static function isDisposable(string $email): array {
        $result = [
            'isDisposable' => false,
            'score' => 0,
            'provider' => ''
        ];

        if (!GMAIL_GUARD_DISPOSABLE_CHECK_ENABLED) {
            return $result;
        }

        $email = strtolower(trim($email));
        $domain = self::getDomain($email);

        if (empty($domain)) {
            return $result;
        }

        // Check against known disposable domains
        if (in_array($domain, self::$disposableDomains)) {
            $result['isDisposable'] = true;
            $result['score'] = 90;
            $result['provider'] = $domain;
            return $result;
        }

        // Check for common disposable patterns
        $disposablePatterns = [
            '/temp.*mail/',
            '/trash.*mail/',
            '/fake.*mail/',
            '/throw.*away/',
            '/guerrilla/',
            '/mailinator/',
            '/spam.*/',
            '/disposable/',
            '/temporary/',
            '/wegwerf/',
            '/jetable/',
            '/^[0-9]{5,}\./', // Numeric prefix domains
            '/minute.*mail/'
        ];

        foreach ($disposablePatterns as $pattern) {
            if (preg_match($pattern, $domain)) {
                $result['isDisposable'] = true;
                $result['score'] = 75;
                $result['provider'] = $domain;
                return $result;
            }
        }

        // Check for suspicious TLDs often used by disposable services
        $suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz'];
        foreach ($suspiciousTlds as $tld) {
            if (substr($domain, -strlen($tld)) === $tld) {
                $result['score'] = 40;
                return $result;
            }
        }

        return $result;
    }

    /**
     * Get domain from email
     */
    private static function getDomain(string $email): string {
        $parts = explode('@', $email);
        return isset($parts[1]) ? strtolower($parts[1]) : '';
    }

    /**
     * Add custom disposable domain to list
     */
    public static function addDisposableDomain(string $domain): void {
        $domain = strtolower(trim($domain));
        if (!in_array($domain, self::$disposableDomains)) {
            self::$disposableDomains[] = $domain;
        }
    }

    /**
     * Get list of disposable domains
     */
    public static function getDisposableDomains(): array {
        return self::$disposableDomains;
    }

    /**
     * Load custom disposable domains from database/config
     */
    public static function loadCustomDomains(): void {
        if (!defined('GMAIL_GUARD_CUSTOM_DISPOSABLE_DOMAINS')) {
            return;
        }

        $customDomains = GMAIL_GUARD_CUSTOM_DISPOSABLE_DOMAINS;
        if (empty($customDomains)) {
            return;
        }

        $domains = array_map('trim', explode("\n", $customDomains));
        $domains = array_map('strtolower', $domains);
        $domains = array_filter($domains);

        foreach ($domains as $domain) {
            self::addDisposableDomain($domain);
        }
    }

    /**
     * Check email against external disposable email API
     */
    public static function checkViaAPI(string $email): array {
        $result = [
            'isDisposable' => false,
            'score' => 0,
            'source' => ''
        ];

        if (!GMAIL_GUARD_DISPOSABLE_API_ENABLED) {
            return $result;
        }

        $domain = self::getDomain($email);
        if (empty($domain)) {
            return $result;
        }

        try {
            // Using disposable.debounce.io API (free, no key required)
            $url = "https://disposable.debounce.io/?email=" . urlencode($domain);

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 3,
                CURLOPT_HTTPHEADER => [
                    'User-Agent: WoltLab-GmailGuard/2.0'
                ]
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200 && $response) {
                $data = json_decode($response, true);

                if (isset($data['disposable']) && $data['disposable'] === true) {
                    $result['isDisposable'] = true;
                    $result['score'] = 85;
                    $result['source'] = 'debounce_api';
                }
            }
        } catch (\Exception $e) {
            // API error - silently fail
            if (defined('GMAIL_GUARD_LOG_ERRORS') && GMAIL_GUARD_LOG_ERRORS) {
                error_log('GmailGuard Disposable API Error: ' . $e->getMessage());
            }
        }

        return $result;
    }
}
