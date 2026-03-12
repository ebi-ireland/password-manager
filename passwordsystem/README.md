# 🔐 SecureVault – Personal Password Manager
### Spring Boot | Java 21 | Full-Stack Web Application

---

## 📋 Assignment Coverage Map

| Requirement | Implementation | File(s) |
|---|---|---|
| ✅ Input Validation (15%) | `@NotBlank`, `@Email`, `@Size`, `@Pattern` + BindingResult | `RegistrationDto.java`, `PasswordEntryDto.java` |
| ✅ Regular Expressions (15%) | Username regex `^[a-zA-Z0-9_]+$`, Password strength regex, URL regex | `RegistrationDto.java`, `PasswordEntryDto.java` |
| ✅ SQL Injection / Prepared Statements (15%) | Spring Data JPA uses Prepared Statements automatically | `UserRepository.java`, `PasswordEntryRepository.java` |
| ✅ Unit Tests (10%) | 22 tests across 3 test classes (all PASS) | `EncryptionServiceTest.java`, `InputValidationTest.java`, `MfaServiceTest.java` |
| ✅ Exception Handling (10%) | Custom exception hierarchy + `@ControllerAdvice` global handler | `PasswordManagerException.java`, `GlobalExceptionHandler.java` |
| ✅ Immutable / Access Modifiers (7%) | `private` fields, public getters/setters, no setter for `id` / `createdAt` | `User.java`, `PasswordEntry.java` |
| ✅ Logging – minimal (3%) | SLF4J, WARN level globally, INFO for app only, NO sensitive data logged | All service classes |
| ✅ Password Encryption + SALT (15%) | BCrypt(12) for master password, AES-256-GCM + PBKDF2+SALT for stored passwords | `EncryptionService.java`, `SecurityConfig.java` |
| ✅ MFA / OTP (10%) | TOTP (Google Authenticator compatible), QR code setup, 6-digit verification | `MfaService.java`, `AuthController.java` |
| ✅ Static Analysis (5%) | Run `mvn checkstyle:check` or SpotBugs/SonarLint in IDE | See section below |
| ✅ Documentation (15%) | This README + inline Javadoc comments throughout code | All files |

---

## 🚀 How to Run

### Prerequisites
- Java 21+
- Maven 3.8+

### Start the application
```bash
mvn spring-boot:run
```

Then open: **http://localhost:8080**

### Run Unit Tests
```bash
mvn test
```

### Run Standalone Tests (no Maven needed)
```bash
cd standalone-tests
javac StandaloneEncryptionTest.java
java StandaloneEncryptionTest
# Expected: 22 PASSED, 0 FAILED
```

---

## 🏗️ Architecture

```
com.security.passwordmanager/
├── config/
│   └── SecurityConfig.java          # Spring Security, BCrypt, session config
├── controller/
│   ├── AuthController.java          # Register, Login, MFA setup & verify
│   └── PasswordController.java      # Dashboard, CRUD for password entries
├── dto/
│   ├── RegistrationDto.java         # Input validation + regex for registration
│   └── PasswordEntryDto.java        # Input validation + URL regex
├── exception/
│   ├── PasswordManagerException.java # Custom exception hierarchy
│   └── GlobalExceptionHandler.java  # @ControllerAdvice – catches all errors
├── model/
│   ├── User.java                    # Private fields, controlled accessors
│   └── PasswordEntry.java           # Private fields, immutable id/createdAt
├── repository/
│   ├── UserRepository.java          # JPA (Prepared Statements = SQL injection safe)
│   └── PasswordEntryRepository.java # JPA (Prepared Statements)
├── service/
│   ├── EncryptionService.java       # AES-256-GCM + PBKDF2 + SALT
│   ├── MfaService.java              # TOTP one-time password (MFA)
│   ├── PasswordEntryService.java    # Business logic for password CRUD
│   └── UserService.java             # Registration, BCrypt hashing, Spring Security
```

---

## 🔒 Security Features Detail

### 1. Password Encryption with SALT
- **Master password** (login): BCrypt strength 12 — auto-generates random salt per user
- **Stored passwords**: AES-256-GCM + PBKDF2WithHmacSHA256 (310,000 iterations)
  - Fresh 128-bit random SALT generated for every encryption
  - Fresh 96-bit random IV generated for every encryption
  - Salt + IV packed alongside ciphertext → unique output each time

### 2. MFA / OTP
- TOTP (RFC 6238) — compatible with Google Authenticator, Authy, 1Password
- QR code generated at `/mfa/setup`
- 6-digit code required after login if MFA is enabled
- `±1 time-step` window to handle minor clock skew

### 3. SQL Injection Prevention
- Spring Data JPA translates method names to Prepared Statements automatically
- No raw SQL anywhere in the codebase
- All parameters are bound via JPA `@Query` or method-name derivation

### 4. Input Validation
- Username: `^[a-zA-Z0-9_]+$` — blocks SQL injection characters, XSS attempts
- Password: must contain uppercase, lowercase, digit, special character
- Email: `@Email` annotation (RFC-5321 compliant)
- URL: regex blocks `javascript:` URIs (XSS vector)

### 5. Access Modifiers (Immutable Design)
- All entity fields are `private`
- `id` and `createdAt` have **no public setter** — immutable once set by JPA
- `mfaSecret` is private, only accessed via controlled service methods

### 6. Logging
- Root level: `WARN` — no framework noise
- App level: `INFO` — only operational events (user registered, entry created)
- **Never logs**: passwords, tokens, OTP codes, session IDs, or user credentials

### 7. Exception Handling
- Custom exception hierarchy under `PasswordManagerException`
- `@ControllerAdvice` catches all exceptions, returns friendly error page
- Encryption errors: logs only exception class name, never the message

---

## 🔍 Static Analysis Instructions

In your IDE (IntelliJ IDEA / Eclipse):
1. Install **SonarLint** plugin
2. Right-click project → "Analyze with SonarLint"
3. Screenshot the findings and document in your report

Via Maven:
```bash
mvn spotbugs:check
mvn checkstyle:check
```

Common findings to discuss in report:
- SonarLint may flag the dev-only fallback master key — note this is intentional for dev mode
- SpotBugs may flag unchecked casts — document why they are safe in context

---

## 🎥 Video Presentation Guide

Suggested structure (5 min):
1. **Intro** (30s): Name, project overview — "SecureVault, a personal password manager built with Spring Boot"
2. **Demo** (2min): Register → Login → MFA setup with QR code → Add a password → Reveal it
3. **Code walkthrough** (2min): Show `EncryptionService` (SALT), `SecurityConfig` (BCrypt), `RegistrationDto` (regex), `GlobalExceptionHandler`
4. **Tests** (30s): Run `java StandaloneEncryptionTest` live — show 22 PASSED
