package com.security.passwordmanager.service;

import com.security.passwordmanager.exception.PasswordManagerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * EncryptionService – AES-256-GCM encryption for stored passwords.
 * Uses PBKDF2 with SALT for key derivation.
 * Demonstrates: Password Encryption with SALT requirement.
 */
@Service
public class EncryptionService {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);

    // AES-GCM constants
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;    // 96-bit IV recommended for GCM
    private static final int GCM_TAG_LENGTH = 128;   // 128-bit auth tag

    // PBKDF2 key derivation constants
    private static final String KEY_FACTORY = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH = 16;       // 128-bit salt
    private static final int ITERATIONS = 310_000;   // OWASP recommended iterations
    private static final int KEY_LENGTH = 256;        // 256-bit AES key

    // Master encryption password from environment (fallback for dev)
    private static final String MASTER_KEY = System.getenv().getOrDefault(
        "ENCRYPTION_MASTER_KEY", "Dev-Only-Change-In-Production-32chars!"
    );

    /**
     * Encrypts a plaintext password using AES-256-GCM.
     * A fresh random SALT and IV are generated for every encryption.
     *
     * @param plaintext the password to encrypt
     * @return Base64-encoded string containing [salt + iv + ciphertext]
     */
    public String encrypt(String plaintext) {
        try {
            // 1. Generate random SALT for key derivation
            byte[] salt = new byte[SALT_LENGTH];
            new SecureRandom().nextBytes(salt);

            // 2. Derive AES-256 key from master key + salt (PBKDF2)
            SecretKey secretKey = deriveKey(MASTER_KEY.toCharArray(), salt);

            // 3. Generate random IV for AES-GCM
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            // 4. Encrypt
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

            // 5. Pack: [salt (16) | iv (12) | ciphertext]
            ByteBuffer buffer = ByteBuffer.allocate(salt.length + iv.length + ciphertext.length);
            buffer.put(salt);
            buffer.put(iv);
            buffer.put(ciphertext);

            return Base64.getEncoder().encodeToString(buffer.array());

        } catch (Exception e) {
            logger.error("Encryption failed: {}", e.getClass().getSimpleName());
            throw new PasswordManagerException.EncryptionException("Failed to encrypt", e);
        }
    }

    /**
     * Decrypts a previously encrypted password.
     *
     * @param encryptedBase64 Base64-encoded [salt + iv + ciphertext]
     * @return the original plaintext password
     */
    public String decrypt(String encryptedBase64) {
        try {
            byte[] decoded = Base64.getDecoder().decode(encryptedBase64);
            ByteBuffer buffer = ByteBuffer.wrap(decoded);

            // 1. Extract salt
            byte[] salt = new byte[SALT_LENGTH];
            buffer.get(salt);

            // 2. Extract IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            buffer.get(iv);

            // 3. Extract ciphertext
            byte[] ciphertext = new byte[buffer.remaining()];
            buffer.get(ciphertext);

            // 4. Re-derive key using the same salt
            SecretKey secretKey = deriveKey(MASTER_KEY.toCharArray(), salt);

            // 5. Decrypt
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            byte[] plaintext = cipher.doFinal(ciphertext);

            return new String(plaintext);

        } catch (Exception e) {
            logger.error("Decryption failed: {}", e.getClass().getSimpleName());
            throw new PasswordManagerException.EncryptionException("Failed to decrypt", e);
        }
    }

    /**
     * Derives a 256-bit AES key using PBKDF2WithHmacSHA256 + SALT.
     * This is the core of the "Password Encryption with SALT" requirement.
     */
    private SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY);
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}
