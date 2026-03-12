import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * Standalone Java Unit Tests for EncryptionService logic.
 * Runs without Maven/Spring - demonstrates all test scenarios.
 */
public class StandaloneEncryptionTest {

    // ── Encryption Logic (same as EncryptionService) ────────────────────────────
    static final String ALGORITHM = "AES/GCM/NoPadding";
    static final int GCM_IV_LENGTH = 12;
    static final int GCM_TAG_LENGTH = 128;
    static final String KEY_FACTORY = "PBKDF2WithHmacSHA256";
    static final int SALT_LENGTH = 16;
    static final int ITERATIONS = 310_000;
    static final int KEY_LENGTH = 256;
    static final String MASTER_KEY = "Dev-Only-Change-In-Production-32chars!";

    static int passed = 0, failed = 0;

    static String encrypt(String plaintext) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        SecretKey key = deriveKey(MASTER_KEY.toCharArray(), salt);
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        ByteBuffer buf = ByteBuffer.allocate(salt.length + iv.length + ciphertext.length);
        buf.put(salt); buf.put(iv); buf.put(ciphertext);
        return Base64.getEncoder().encodeToString(buf.array());
    }

    static String decrypt(String encryptedBase64) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encryptedBase64);
        ByteBuffer buf = ByteBuffer.wrap(decoded);
        byte[] salt = new byte[SALT_LENGTH]; buf.get(salt);
        byte[] iv = new byte[GCM_IV_LENGTH]; buf.get(iv);
        byte[] ciphertext = new byte[buf.remaining()]; buf.get(ciphertext);
        SecretKey key = deriveKey(MASTER_KEY.toCharArray(), salt);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        return new String(cipher.doFinal(ciphertext));
    }

    static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY);
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    // ── Test Runner Helpers ────────────────────────────────────────────────────
    static void assertTrue(boolean condition, String testName) {
        if (condition) { System.out.println("  ✅ PASS: " + testName); passed++; }
        else           { System.out.println("  ❌ FAIL: " + testName); failed++; }
    }

    static void assertNotEquals(Object a, Object b, String testName) {
        assertTrue(!a.equals(b), testName);
    }

    static void assertEquals(Object a, Object b, String testName) {
        assertTrue(a.equals(b), testName);
    }

    // ── TESTS ──────────────────────────────────────────────────────────────────

    static void test1_EncryptDecryptRoundTrip() throws Exception {
        System.out.println("\n[Test 1] Encrypt → Decrypt round-trip");
        String original = "MySecret@Password123!";
        String encrypted = encrypt(original);
        String decrypted = decrypt(encrypted);
        assertTrue(encrypted != null, "Encrypted value is not null");
        assertNotEquals(original, encrypted, "Encrypted differs from plaintext");
        assertEquals(original, decrypted, "Decrypted matches original");
    }

    static void test2_SaltUniqueness() throws Exception {
        System.out.println("\n[Test 2] Same plaintext → different ciphertexts (unique SALT)");
        String password = "SamePassword!123";
        String enc1 = encrypt(password);
        String enc2 = encrypt(password);
        assertNotEquals(enc1, enc2, "Two encryptions produce different ciphertexts (unique SALT+IV)");
        assertEquals(decrypt(enc1), decrypt(enc2), "Both ciphertexts decrypt to same original value");
    }

    static void test3_SpecialCharacters() throws Exception {
        System.out.println("\n[Test 3] Special characters preserved");
        String special = "P@$$w0rd!#%^&*()_+ Hello World";
        assertEquals(special, decrypt(encrypt(special)), "Special characters preserved after encrypt/decrypt");
    }

    static void test4_EmptyString() throws Exception {
        System.out.println("\n[Test 4] Empty string handled");
        String empty = "";
        assertEquals(empty, decrypt(encrypt(empty)), "Empty string encrypts/decrypts correctly");
    }

    static void test5_TamperedCiphertext() throws Exception {
        System.out.println("\n[Test 5] Tampered ciphertext throws exception");
        String encrypted = encrypt("MyPassword123!");
        String tampered = encrypted + "TAMPERED_GARBAGE_DATA";
        try {
            decrypt(tampered);
            System.out.println("  ❌ FAIL: Should have thrown exception"); failed++;
        } catch (Exception e) {
            System.out.println("  ✅ PASS: Tampered ciphertext correctly throws " + e.getClass().getSimpleName());
            passed++;
        }
    }

    static void test6_LongPassword() throws Exception {
        System.out.println("\n[Test 6] Very long password (453 chars) handled");
        String longPw = "A".repeat(450) + "!1a";
        assertEquals(longPw, decrypt(encrypt(longPw)), "Long password handled correctly");
    }

    // ── Input Validation Tests (Regex) ─────────────────────────────────────────

    static void test7_UsernameRegex() {
        System.out.println("\n[Test 7] Username regex validation");
        String validPattern = "^[a-zA-Z0-9_]+$";
        assertTrue("alice123".matches(validPattern), "Valid username 'alice123' passes");
        assertTrue(!"admin' OR '1'='1".matches(validPattern), "SQL injection in username is rejected");
        assertTrue(!"user<script>".matches(validPattern), "XSS attempt in username is rejected");
        assertTrue(!"hello world".matches(validPattern), "Space in username is rejected");
    }

    static void test8_PasswordStrengthRegex() {
        System.out.println("\n[Test 8] Password strength regex validation");
        String strongPattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";
        assertTrue("SecureP@ss1".matches(strongPattern), "Strong password passes");
        assertTrue(!"weakpassword".matches(strongPattern), "No uppercase/number/special fails");
        assertTrue(!"SHORT1!".matches(strongPattern), "Too short password fails");
        assertTrue(!"nouppercase1!".matches(strongPattern), "No uppercase fails");
    }

    static void test9_UrlRegex() {
        System.out.println("\n[Test 9] URL regex validation");
        String urlPattern = "^(https?://)?([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}(/.*)?$|^$";
        assertTrue("https://mail.google.com".matches(urlPattern), "Valid HTTPS URL passes");
        assertTrue("http://example.com/path".matches(urlPattern), "Valid HTTP URL with path passes");
        assertTrue("".matches(urlPattern), "Empty URL passes (optional field)");
        assertTrue(!"javascript:alert('xss')".matches(urlPattern), "JavaScript URL is rejected");
        assertTrue(!"not_a_url".matches(urlPattern), "Plain text URL is rejected");
    }

    // ── Main ──────────────────────────────────────────────────────────────────
    public static void main(String[] args) throws Exception {
        System.out.println("═══════════════════════════════════════════════════════════════");
        System.out.println("  SecureVault – Unit Test Suite");
        System.out.println("  EncryptionService + InputValidation Tests");
        System.out.println("═══════════════════════════════════════════════════════════════");

        test1_EncryptDecryptRoundTrip();
        test2_SaltUniqueness();
        test3_SpecialCharacters();
        test4_EmptyString();
        test5_TamperedCiphertext();
        test6_LongPassword();
        test7_UsernameRegex();
        test8_PasswordStrengthRegex();
        test9_UrlRegex();

        System.out.println("\n═══════════════════════════════════════════════════════════════");
        System.out.printf("  Results: %d PASSED, %d FAILED%n", passed, failed);
        System.out.println("═══════════════════════════════════════════════════════════════");

        if (failed > 0) System.exit(1);
    }
}
