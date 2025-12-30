<?php
namespace wcf\data\user;

use wcf\system\WCF;

/**
 * Integration with StopForumSpam.com API.
 *
 * @author  Custom Development
 * @license Apache License 2.0
 */
class StopForumSpamChecker {

    const API_URL = 'https://api.stopforumspam.org/api';

    /**
     * Check email and IP against StopForumSpam database
     */
    public static function check(string $email, string $ipAddress, string $username = ''): array {
        $result = [
            'spam' => false,
            'confidence' => 0,
            'reasons' => [],
            'score' => 0
        ];

        if (!GMAIL_GUARD_SFS_ENABLED) {
            return $result;
        }

        try {
            $params = [
                'email' => $email,
                'ip' => $ipAddress,
                'json' => '1'
            ];

            if (!empty($username)) {
                $params['username'] = $username;
            }

            $url = self::API_URL . '?' . http_build_query($params);

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 5,
                CURLOPT_HTTPHEADER => [
                    'User-Agent: WoltLab-GmailGuard/2.0'
                ]
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200 && $response) {
                $data = json_decode($response, true);

                if (isset($data['success']) && $data['success'] === 1) {
                    // Check email
                    if (isset($data['email']['appears']) && $data['email']['appears'] === 1) {
                        $result['spam'] = true;
                        $result['reasons'][] = 'sfs_email_listed';
                        $result['score'] += 60;

                        $frequency = $data['email']['frequency'] ?? 0;
                        if ($frequency > 10) {
                            $result['score'] += 20; // Heavily reported
                        }
                    }

                    // Check IP
                    if (isset($data['ip']['appears']) && $data['ip']['appears'] === 1) {
                        $result['spam'] = true;
                        $result['reasons'][] = 'sfs_ip_listed';
                        $result['score'] += 40;

                        $frequency = $data['ip']['frequency'] ?? 0;
                        if ($frequency > 10) {
                            $result['score'] += 15;
                        }
                    }

                    // Check username if provided
                    if (!empty($username) && isset($data['username']['appears']) && $data['username']['appears'] === 1) {
                        $result['spam'] = true;
                        $result['reasons'][] = 'sfs_username_listed';
                        $result['score'] += 30;
                    }

                    // Calculate confidence based on frequency
                    if ($result['spam']) {
                        $emailFreq = $data['email']['frequency'] ?? 0;
                        $ipFreq = $data['ip']['frequency'] ?? 0;
                        $totalFreq = $emailFreq + $ipFreq;

                        if ($totalFreq > 50) {
                            $result['confidence'] = 95;
                        } elseif ($totalFreq > 20) {
                            $result['confidence'] = 85;
                        } elseif ($totalFreq > 5) {
                            $result['confidence'] = 70;
                        } else {
                            $result['confidence'] = 50;
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            // API error - log but don't block registration
            if (GMAIL_GUARD_LOG_ERRORS) {
                error_log('GmailGuard StopForumSpam API Error: ' . $e->getMessage());
            }
        }

        return $result;
    }

    /**
     * Report spam to StopForumSpam (requires API key)
     */
    public static function reportSpam(string $email, string $ipAddress, string $username, string $evidence = ''): bool {
        if (!GMAIL_GUARD_SFS_ENABLED || empty(GMAIL_GUARD_SFS_API_KEY)) {
            return false;
        }

        try {
            $params = [
                'username' => $username,
                'email' => $email,
                'ip_addr' => $ipAddress,
                'api_key' => GMAIL_GUARD_SFS_API_KEY,
                'evidence' => $evidence ?: 'Reported via WoltLab GmailGuard'
            ];

            $url = 'https://www.stopforumspam.com/add.php';

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query($params),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 5
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            return $httpCode === 200;
        } catch (\Exception $e) {
            if (GMAIL_GUARD_LOG_ERRORS) {
                error_log('GmailGuard StopForumSpam Report Error: ' . $e->getMessage());
            }
            return false;
        }
    }

    /**
     * Get statistics from StopForumSpam
     */
    public static function getStats(): array {
        try {
            $url = 'https://api.stopforumspam.org/api?stats&json';

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 5
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200 && $response) {
                return json_decode($response, true) ?: [];
            }
        } catch (\Exception $e) {
            // Ignore errors
        }

        return [];
    }
}
