package com.security.passwordmanager.service;

import com.security.passwordmanager.exception.PasswordManagerException;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

/**
 * MfaService – TOTP-based Multi-Factor Authentication.
 * Generates secrets, QR codes, and validates One-Time Passwords.
 * Demonstrates: Authentication / MFA using OTP requirement.
 */
@Service
public class MfaService {

    private static final Logger logger = LoggerFactory.getLogger(MfaService.class);
    private static final String ISSUER = "SecurePasswordManager";

    /**
     * Generates a new TOTP secret key for the user.
     * @return Base32-encoded secret (to be stored encrypted)
     */
    public String generateSecret() {
        return new DefaultSecretGenerator().generate();
    }

    /**
     * Generates a QR code data URI for Google Authenticator / Authy setup.
     * @param username the user's username (shown in authenticator app)
     * @param secret   the TOTP secret
     * @return data URI string for an HTML <img> tag
     */
    public String generateQrCodeDataUri(String username, String secret) {
        try {
            QrData qrData = new QrData.Builder()
                .label(username)
                .secret(secret)
                .issuer(ISSUER)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

            QrGenerator generator = new ZxingPngQrGenerator();
            byte[] imageData = generator.generate(qrData);
            return getDataUriForImage(imageData, generator.getImageMimeType());

        } catch (QrGenerationException e) {
            logger.error("QR code generation failed for user setup");
            throw new PasswordManagerException("Failed to generate MFA QR code", e);
        }
    }

    /**
     * Validates a 6-digit TOTP code against the user's secret.
     * Allows a ±1 time-step window to handle clock skew.
     *
     * @param secret the user's TOTP secret
     * @param code   the 6-digit OTP entered by user
     * @return true if valid, false otherwise
     */
    public boolean validateOtp(String secret, String code) {
        try {
            CodeGenerator codeGenerator = new DefaultCodeGenerator();
            CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, new SystemTimeProvider());
            boolean valid = verifier.isValidCode(secret, code);
            if (!valid) {
                logger.warn("Invalid OTP attempt detected");
            }
            return valid;
        } catch (Exception e) {
            logger.error("OTP validation error: {}", e.getClass().getSimpleName());
            return false;
        }
    }
}
