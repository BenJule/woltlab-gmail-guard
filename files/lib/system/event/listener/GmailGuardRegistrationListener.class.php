<?php
namespace wcf\system\event\listener;

use wcf\data\user\GmailValidator;
use wcf\form\RegisterForm;
use wcf\system\exception\UserInputException;
use wcf\system\request\LinkHandler;
use wcf\system\WCF;
use wcf\util\HeaderUtil;

/**
 * Event listener for user registration to validate Gmail addresses.
 *
 * @author  Custom Development
 * @license Apache License 2.0
 */
class GmailGuardRegistrationListener implements IParameterizedEventListener {

    /**
     * Stores validation result to avoid duplicate checks
     */
    private static $validationCache = [];

    /**
     * @inheritDoc
     */
    public function execute($eventObj, $className, $eventName, array &$parameters) {
        if (!($eventObj instanceof RegisterForm)) {
            return;
        }

        // Only process if Gmail Guard is enabled
        if (!GMAIL_GUARD_ENABLED) {
            return;
        }

        switch ($eventName) {
            case 'validate':
                $this->validateEmail($eventObj);
                break;

            case 'saved':
                $this->handleSuspiciousRegistration($eventObj);
                break;
        }
    }

    /**
     * Validate email address during registration
     */
    private function validateEmail(RegisterForm $form) {
        $email = $form->email;

        // Skip if not a Gmail address
        if (!GmailValidator::isGmailAddress($email)) {
            return;
        }

        // Perform validation
        $validation = GmailValidator::validateGmailAddress($email);

        // Cache result for later use
        self::$validationCache[$email] = $validation;

        // Handle suspicious addresses based on action mode
        if ($validation['suspicious']) {
            $action = GMAIL_GUARD_ACTION;

            switch ($action) {
                case 'block':
                    // Block registration completely
                    $reason = GmailValidator::getSuspiciousReason($validation['reasons']);
                    throw new UserInputException(
                        'email',
                        'gmailSuspicious',
                        ['reason' => $reason, 'score' => $validation['score']]
                    );
                    break;

                case 'verify':
                    // Additional verification will be handled in saved event
                    // Just log for now
                    if (GMAIL_GUARD_LOG_SUSPICIOUS) {
                        $this->logSuspiciousAttempt($email, $validation);
                    }
                    break;

                case 'moderate':
                    // Will be handled in saved event - account stays inactive
                    if (GMAIL_GUARD_LOG_SUSPICIOUS) {
                        $this->logSuspiciousAttempt($email, $validation);
                    }
                    break;
            }
        }
    }

    /**
     * Handle post-registration actions for suspicious addresses
     */
    private function handleSuspiciousRegistration(RegisterForm $form) {
        $email = $form->email;

        // Get cached validation or revalidate
        if (!isset(self::$validationCache[$email])) {
            self::$validationCache[$email] = GmailValidator::validateGmailAddress($email);
        }

        $validation = self::$validationCache[$email];

        if ($validation['suspicious']) {
            $action = GMAIL_GUARD_ACTION;

            switch ($action) {
                case 'verify':
                    $this->applyAdditionalVerification($form);
                    break;

                case 'moderate':
                    $this->requireModeration($form);
                    break;
            }
        }
    }

    /**
     * Apply additional verification requirements
     */
    private function applyAdditionalVerification(RegisterForm $form) {
        // Set custom session flag for additional verification
        WCF::getSession()->register('gmailGuardVerificationRequired', true);
        WCF::getSession()->register('gmailGuardEmail', $form->email);

        // Show info message to user
        WCF::getTPL()->assign([
            'gmailGuardVerificationRequired' => true,
            'gmailGuardMessage' => WCF::getLanguage()->get('wcf.user.gmail.verification.required')
        ]);
    }

    /**
     * Mark account for moderation
     */
    private function requireModeration(RegisterForm $form) {
        // The user account has been created at this point
        // We need to set a custom user option or flag for admin review

        if (GMAIL_GUARD_NOTIFICATION_EMAIL) {
            $this->notifyAdministrators($form->email);
        }

        // Show message to user
        WCF::getTPL()->assign([
            'gmailGuardModerationRequired' => true,
            'gmailGuardMessage' => WCF::getLanguage()->get('wcf.user.gmail.moderation.required')
        ]);
    }

    /**
     * Log suspicious registration attempt
     */
    private function logSuspiciousAttempt(string $email, array $validation) {
        $logMessage = sprintf(
            "[GmailGuard] Suspicious Gmail registration attempt: %s | Score: %d | Reasons: %s | IP: %s | Time: %s",
            $email,
            $validation['score'],
            implode(', ', $validation['reasons']),
            WCF::getSession()->ipAddress,
            date('Y-m-d H:i:s')
        );

        error_log($logMessage);

        // Optionally store in database for admin panel
        if (GMAIL_GUARD_DB_LOG) {
            $this->storeInDatabase($email, $validation);
        }
    }

    /**
     * Store suspicious attempt in database
     */
    private function storeInDatabase(string $email, array $validation) {
        $sql = "INSERT INTO wcf" . WCF_N . "_gmail_guard_log
                (email, score, reasons, ipAddress, time)
                VALUES (?, ?, ?, ?, ?)";
        $statement = WCF::getDB()->prepareStatement($sql);
        $statement->execute([
            $email,
            $validation['score'],
            json_encode($validation['reasons']),
            WCF::getSession()->ipAddress,
            TIME_NOW
        ]);
    }

    /**
     * Notify administrators about suspicious registration
     */
    private function notifyAdministrators(string $email) {
        $adminEmail = GMAIL_GUARD_NOTIFICATION_EMAIL;

        if (empty($adminEmail)) {
            return;
        }

        $subject = WCF::getLanguage()->get('wcf.user.gmail.admin.notification.subject');
        $message = WCF::getLanguage()->getDynamicVariable(
            'wcf.user.gmail.admin.notification.message',
            ['email' => $email]
        );

        // Send email via WoltLab mail system
        $mail = new \wcf\system\mail\Mail();
        $mail->addRecipient(new \wcf\system\mail\Mailbox($adminEmail));
        $mail->setSubject($subject);
        $mail->setBody(new \wcf\system\mail\mime\MimePartFacade([
            new \wcf\system\mail\mime\TextMimePart($message)
        ]));
        $mail->send();
    }
}
