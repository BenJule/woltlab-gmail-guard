<?php
namespace wcf\system\event\listener;

use wcf\data\user\GmailValidator;
use wcf\data\user\AntiBotValidator;
use wcf\data\user\RateLimiter;
use wcf\form\RegisterForm;
use wcf\system\exception\UserInputException;
use wcf\system\WCF;

/**
 * Enhanced event listener with comprehensive anti-spam validation.
 *
 * @author  Custom Development
 * @license Apache License 2.0
 * @version 2.0.0
 */
class GmailGuardRegistrationListener implements IParameterizedEventListener {

    private static $validationCache = [];

    /**
     * @inheritDoc
     */
    public function execute($eventObj, $className, $eventName, array &$parameters) {
        if (!($eventObj instanceof RegisterForm)) {
            return;
        }

        if (!GMAIL_GUARD_ENABLED) {
            return;
        }

        switch ($eventName) {
            case 'readFormParameters':
                $this->readFormParameters($eventObj);
                break;

            case 'validate':
                $this->validateRegistration($eventObj);
                break;

            case 'saved':
                $this->handlePostRegistration($eventObj);
                break;
        }
    }

    /**
     * Read additional form parameters for anti-bot validation
     */
    private function readFormParameters(RegisterForm $form) {
        // Read honeypot field
        if (GMAIL_GUARD_HONEYPOT_ENABLED) {
            $honeypotField = AntiBotValidator::getHoneypotFieldName();
            if (isset($_POST[$honeypotField])) {
                WCF::getSession()->register('gmailGuardHoneypot', $_POST[$honeypotField]);
            }
        }

        // Read timing token
        if (GMAIL_GUARD_TIMING_CHECK_ENABLED && isset($_POST['gmail_guard_timing'])) {
            WCF::getSession()->register('gmailGuardTiming', $_POST['gmail_guard_timing']);
        }
    }

    /**
     * Comprehensive validation
     */
    private function validateRegistration(RegisterForm $form) {
        $email = $form->email;
        $username = $form->username ?? '';
        $ipAddress = WCF::getSession()->ipAddress;

        // Prepare form data for validation
        $formData = [];

        if (GMAIL_GUARD_HONEYPOT_ENABLED) {
            $formData['honeypot'] = WCF::getSession()->getVar('gmailGuardHoneypot') ?? '';
        }

        if (GMAIL_GUARD_TIMING_CHECK_ENABLED) {
            $formData['timing_token'] = WCF::getSession()->getVar('gmailGuardTiming') ?? '';
        }

        // Perform comprehensive validation
        $validation = GmailValidator::validateEmail($email, $ipAddress, $username, $formData);

        // Cache result
        self::$validationCache[$email] = $validation;

        // Handle validation result
        if ($validation['blocked'] || !$validation['valid']) {
            $this->handleBlockedRegistration($email, $validation);
        } elseif ($validation['suspicious']) {
            $this->handleSuspiciousRegistration($email, $validation);
        }
    }

    /**
     * Handle blocked registration
     */
    private function handleBlockedRegistration(string $email, array $validation) {
        $reasons = $validation['reasons'];
        $primaryReason = $reasons[0] ?? 'generic';

        // Get appropriate error message
        $errorMessage = $this->getErrorMessage($primaryReason, $validation);

        throw new UserInputException(
            'email',
            'gmailGuardBlocked',
            [
                'reason' => $errorMessage,
                'score' => $validation['score'],
                'details' => $validation['details'] ?? []
            ]
        );
    }

    /**
     * Handle suspicious registration that's not blocked
     */
    private function handleSuspiciousRegistration(string $email, array $validation) {
        if (GMAIL_GUARD_LOG_SUSPICIOUS) {
            $this->logSuspiciousAttempt($email, $validation);
        }

        $action = GMAIL_GUARD_ACTION;

        if ($action === 'verify') {
            // Set session flag for additional verification
            WCF::getSession()->register('gmailGuardVerificationRequired', true);
            WCF::getSession()->register('gmailGuardScore', $validation['score']);
        }
    }

    /**
     * Handle post-registration actions
     */
    private function handlePostRegistration(RegisterForm $form) {
        $email = $form->email;

        if (!isset(self::$validationCache[$email])) {
            return;
        }

        $validation = self::$validationCache[$email];

        if (!$validation['suspicious']) {
            return;
        }

        $action = GMAIL_GUARD_ACTION;

        if ($action === 'moderate') {
            if (GMAIL_GUARD_NOTIFICATION_EMAIL) {
                $this->notifyAdministrators($email, $validation);
            }
        }

        // Clear session data
        WCF::getSession()->unregister('gmailGuardHoneypot');
        WCF::getSession()->unregister('gmailGuardTiming');
    }

    /**
     * Get error message for specific reason
     */
    private function getErrorMessage(string $reason, array $validation): string {
        $lang = WCF::getLanguage();

        switch ($reason) {
            case 'blacklisted':
                return $lang->get('wcf.user.gmail.error.blacklisted');

            case 'ip_banned':
                $timeRemaining = $validation['details']['ban_time_remaining'] ?? 0;
                $hours = ceil($timeRemaining / 3600);
                return $lang->getDynamicVariable('wcf.user.gmail.error.ip_banned', ['hours' => $hours]);

            case 'rate_limited':
                return $lang->get('wcf.user.gmail.error.rate_limited');

            case 'disposable_email':
            case 'disposable_email_api':
                return $lang->get('wcf.user.gmail.error.disposable');

            case 'honeypot_filled':
                return $lang->get('wcf.user.gmail.error.bot_detected');

            case 'sfs_email_listed':
            case 'sfs_ip_listed':
                return $lang->get('wcf.user.gmail.error.spam_database');

            case 'outside_allowed_hours':
                $startHour = GMAIL_GUARD_ALLOWED_START_HOUR;
                $endHour = GMAIL_GUARD_ALLOWED_END_HOUR;
                return $lang->getDynamicVariable('wcf.user.gmail.error.time_restricted', [
                    'start' => $startHour,
                    'end' => $endHour
                ]);

            default:
                return GmailValidator::getSuspiciousReason($validation['reasons']);
        }
    }

    /**
     * Log suspicious attempt
     */
    private function logSuspiciousAttempt(string $email, array $validation) {
        $logMessage = sprintf(
            "[GmailGuard v2.0] Suspicious registration: %s | Score: %d | Reasons: %s | IP: %s",
            $email,
            $validation['score'],
            implode(', ', $validation['reasons']),
            WCF::getSession()->ipAddress
        );

        error_log($logMessage);

        if (GMAIL_GUARD_DB_LOG) {
            $this->storeInDatabase($email, $validation);
        }
    }

    /**
     * Store in database
     */
    private function storeInDatabase(string $email, array $validation) {
        $sql = "INSERT INTO wcf" . WCF_N . "_gmail_guard_log
                (email, score, reasons, ipAddress, userAgent, details, time)
                VALUES (?, ?, ?, ?, ?, ?, ?)";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([
            $email,
            $validation['score'],
            json_encode($validation['reasons']),
            WCF::getSession()->ipAddress,
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            json_encode($validation['details'] ?? []),
            TIME_NOW
        ]);
    }

    /**
     * Notify administrators
     */
    private function notifyAdministrators(string $email, array $validation) {
        $adminEmail = GMAIL_GUARD_NOTIFICATION_EMAIL;

        if (empty($adminEmail)) {
            return;
        }

        try {
            $subject = WCF::getLanguage()->get('wcf.user.gmail.admin.notification.subject');
            $message = WCF::getLanguage()->getDynamicVariable(
                'wcf.user.gmail.admin.notification.message',
                [
                    'email' => $email,
                    'score' => $validation['score'],
                    'reasons' => implode(', ', $validation['reasons'])
                ]
            );

            $mail = new \wcf\system\mail\Mail();
            $mail->addRecipient(new \wcf\system\mail\Mailbox($adminEmail));
            $mail->setSubject($subject);
            $mail->setBody(new \wcf\system\mail\mime\MimePartFacade([
                new \wcf\system\mail\mime\TextMimePart($message)
            ]));
            $mail->send();
        } catch (\Exception $e) {
            if (GMAIL_GUARD_LOG_ERRORS) {
                error_log('GmailGuard Notification Error: ' . $e->getMessage());
            }
        }
    }
}
