# Secure Student Information System – Login Module

A console-based secure login implementation for the Online Secure Student Information System (SIS), developed as part of a Secure Software Development course project.

---

## What This Does

This is the **login component** of the SIS. It authenticates students, instructors, and administrators using security best practices throughout the SDLC. After a successful login, it displays a role-appropriate menu stub demonstrating Role-Based Access Control (RBAC).

---

## Security Features

| Feature | How It Is Implemented |
|---|---|
| SQL Injection prevention | `PreparedStatement` with `?` placeholders — user input is never concatenated into SQL |
| Password hashing | BCrypt via `jBCrypt` — passwords are never stored in plaintext |
| Brute-force protection | Account locked after **3** failed attempts |
| Input validation | Whitelist regex `[a-zA-Z0-9_]{3,30}` on username; length check on password |
| No information leakage | Both "user not found" and "wrong password" return the same generic message |
| DB errors hidden from user | `SQLException` details go to `stderr` only, never shown to the user |
| Audit logging | Every login attempt (success or failure) is logged with a timestamp to `stderr` |
| Role-Based Access Control | Role is read from the database, never from user input |
| BCrypt DoS prevention | Password input rejected if longer than 72 characters (BCrypt's processing limit) |

---

## Project Requirements Covered

This file directly addresses the following report sections:

- **Security Requirements** – threats mitigated: SQL injection, brute-force, credential exposure, username enumeration
- **Secure Implementation** – defensive code with inline comments referencing each secure coding guideline
- **Secure Testing** – see the test cases section below

---

## File Structure

```
.
├── Login.java     ← main source file (this module)
├── setup.sql      ← creates the database and sample users
└── README.md      ← this file
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| Java | JDK 8 or higher |
| MySQL | 8.x (running on port 3308) |
| jBCrypt library | 0.4 |

**Download jBCrypt:** https://www.mindrot.org/projects/jBCrypt/

---

## Setup Instructions

### 1. Create the database

```bash
mysql -u root -p < setup.sql
```

This creates the `sis_db` database and inserts three sample users.

### 2. Update the DB password in Login.java

Open `Login.java` and change line:

```java
static final String DB_PASS = "your_password_here";
```

to your actual MySQL root password.

### 3. Compile

```bash
javac -cp ".;jbcrypt-0.4.jar" Login.java       # Windows
javac -cp ".:jbcrypt-0.4.jar" Login.java        # macOS / Linux
```

### 4. Run

```bash
java -cp ".;jbcrypt-0.4.jar" Login              # Windows
java -cp ".:jbcrypt-0.4.jar" Login              # macOS / Linux
```

---

## Sample Users (for testing)

| Username | Password | Role |
|---|---|---|
| `student_user` | `Student@123` | Student |
| `prof_smith` | `Instructor@456` | Instructor |
| `admin_user` | `Admin@789` | Admin |

> **Note:** The hashes in `setup.sql` are pre-generated examples. If login fails, re-generate hashes using `BCrypt.hashpw()` and update the `INSERT` statements.

---

## Security Test Cases

The following test cases correspond to the **Secure Testing** section of the project report.

### TC-01 – SQL Injection on Login (Threat: SQL Injection)

| Field | Value |
|---|---|
| **Input** | Username: `' OR '1'='1` |
| **Expected result** | Login fails with "Invalid username or password" |
| **Why it passes** | `PreparedStatement` treats the input as a literal string, not SQL |

---

### TC-02 – Brute-Force Lockout (Threat: Brute-Force Attack)

| Field | Value |
|---|---|
| **Input** | Any valid username with a wrong password, repeated 3 times |
| **Expected result** | Account is locked after the 3rd attempt; subsequent tries are rejected |
| **Why it passes** | `failed_attempts` counter triggers `lockAccount()` at `MAX_ATTEMPTS` |

---

### TC-03 – Username Enumeration (Threat: Information Leakage)

| Field | Value |
|---|---|
| **Input** | A username that does not exist in the database |
| **Expected result** | "Invalid username or password" — identical message to a wrong password |
| **Why it passes** | Both code paths (`!rs.next()` and wrong password) return the same message |

---

### TC-04 – Empty Input (Threat: Input Validation Bypass)

| Field | Value |
|---|---|
| **Input** | Username: *(empty)* |
| **Expected result** | Error: "Username cannot be empty" — no DB query is made |
| **Why it passes** | Input validation runs before any database interaction |

---

### TC-05 – Oversized Password (Threat: Denial of Service via BCrypt)

| Field | Value |
|---|---|
| **Input** | Password longer than 72 characters |
| **Expected result** | Error: "Password exceeds maximum allowed length" |
| **Why it passes** | Length check rejects the input before reaching `BCrypt.checkpw()` |

---

## Audit Log Format

All login attempts are written to `stderr`. To save them to a file:

```bash
java -cp ".:jbcrypt-0.4.jar" Login 2>> audit.log
```

Log format:
```
[AUDIT] 2025-04-28 14:32:01 | user=student_user         | success=true  | reason=success
[AUDIT] 2025-04-28 14:33:15 | user=student_user         | success=false | reason=wrong password
```

---

## Authors

Team project – Secure Software Development Course
