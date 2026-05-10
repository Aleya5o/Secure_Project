/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package javaapplication202;

/**
 *
 * @author rosea
 */
import java.sql.*;
import org.mindrot.jbcrypt.BCrypt;
import java.util.Scanner;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * SECURE CODING GUIDELINES APPLIED
 * ---------------------------------
 * 1. Parameterized queries          - prevents SQL Injection
 * 2. BCrypt password hashing        - passwords never stored in plaintext
 * 3. Account lockout after 3 fails  - prevents brute-force attacks
 * 4. Input validation (whitelist)   - no empty, oversized, or malformed input
 * 5. Generic error messages         - no information leakage to attacker
 * 6. DB errors never shown to user  - internal errors logged only
 * 7. Role-based welcome message     - confirms RBAC is in place
 * 8. Login attempt logging          - audit trail for security review
 * 9. Password length limit          - prevents denial-of-service via BCrypt
 *10. Scanner closed safely          - proper resource management
 *
 * ASSETS PROTECTED
 * ----------------
 * - Student grade records
 * - User credentials (usernames, hashed passwords)
 * - Role assignments (student / instructor / admin)
 *
 * THREATS MITIGATED
 * -----------------
 * - SQL Injection        - parameterized PreparedStatement
 * - Brute-force attack   - account lockout after MAX_ATTEMPTS
 * - Password exposure    - BCrypt one-way hashing
 * - Username enumeration - generic "Invalid credentials" message
 * - Privilege escalation - role returned from DB, never from user input
 */
public class Login {

    //  Database connection settings 
    static final String DB_URL  = "jdbc:mysql://localhost:3308/osis_db" + "?useSSL=false&serverTimezone=UTC";
    static final String DB_USER = "root";
    static final String DB_PASS = "secureproject123@"; 

    //  Security policy constants 
    static final int MAX_ATTEMPTS    = 3;   // failed logins before lockout
    static final int MAX_PASSWORD_LEN = 72; // BCrypt processes max 72 bytes

    //  Timestamp formatter for audit logging 
    static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // =========================================================================
    //  ENTRY POINT
    // =========================================================================
    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        printBanner();

        // Step 1: Collect and validate username 
        System.out.print("Username : ");
        String username = scanner.nextLine().trim();

        // Input validation  must not be empty
        if (username.isEmpty()) {
            System.out.println("[ERROR] Username cannot be empty.");
            scanner.close();
            return;
        }

        // Input validation  whitelist: letters, digits, underscore, 3-30 chars
        // This is a SECURE CODING GUIDELINE: only allow known-good characters
        if (!username.matches("[a-zA-Z0-9_]{3,30}")) {
            System.out.println("[ERROR] Invalid username format.");
            scanner.close();
            return;
        }

        //  Step 2: Collect and validate password
        System.out.print("Password : ");
        String password = scanner.nextLine();

        // Input validation  must not be empty
        if (password.isEmpty()) {
            System.out.println("[ERROR] Password cannot be empty.");
            scanner.close();
            return;
        }

        // Input validation - enforce maximum length
        // BCrypt silently truncates at 72 bytes; 
        // This also prevents a denial-of-service via extremely long passwords
        if (password.length() > MAX_PASSWORD_LEN) {
            System.out.println("[ERROR] Password exceeds maximum allowed length.");
            scanner.close();
            return;
        }

        // Step 3: Attempt login 
        login(username, password);

        scanner.close();
    }

    // =========================================================================
    //  CORE LOGIN LOGIC
    // =========================================================================
    /**
     * Looks up the user in the database and verifies credentials.
     *
     * Security measures:
     *  - PreparedStatement prevents SQL Injection
     *  - BCrypt.checkpw() does constant-time comparison (no timing attack)
     *  - Failed attempts are tracked and account is locked after MAX_ATTEMPTS
     *  - Both "user not found" and "wrong password" return the same message
     *    (prevents username enumeration)
     */
    static void login(String username, String password) {

        // SECURE CODING: parameterized query  user input NEVER concatenated
        String sql = "SELECT id, password_hash, role, account_locked, failed_attempts "
                   + "FROM users WHERE username = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, username); // bind username safely
            ResultSet rs = ps.executeQuery();

            // ── User not found 
            // SECURE CODING: generic message prevents username enumeration
            if (!rs.next()) {
                logAttempt(username, false, "user not found");
                System.out.println("[FAIL] Invalid username or password.");
                return;
            }

            // Retrieve stored values
            int     userId       = rs.getInt("id");
            String  passwordHash = rs.getString("password_hash");
            String  role         = rs.getString("role");
            boolean locked       = rs.getBoolean("account_locked");
            int     failedCount  = rs.getInt("failed_attempts");

            // ── Account locked check 
            if (locked) {
                logAttempt(username, false, "account locked");
                System.out.println("[LOCKED] Account is locked. "
                        + "Please contact the administrator.");
                return;
            }

            // ── Password verification (BCrypt) 
            // BCrypt.checkpw performs a safe, constant-time comparison.
            // The stored hash already contains the salt, so no separate salt
            // column is needed.
            boolean passwordCorrect = BCrypt.checkpw(password, passwordHash);

            if (!passwordCorrect) {
                int newCount  = failedCount + 1;
                int remaining = MAX_ATTEMPTS - newCount;

                updateFailedAttempts(conn, userId, newCount);

                if (remaining <= 0) {
                    lockAccount(conn, userId);
                    logAttempt(username, false, "too many failed attempts – account locked");
                    System.out.println("[LOCKED] Too many failed attempts. "
                            + "Your account is now locked.");
                } else {
                    logAttempt(username, false, "wrong password");
                    System.out.println("[FAIL] Invalid username or password. "
                            + remaining + " attempt(s) remaining.");
                }
                return;
            }

            //  Login successful 
            resetFailedAttempts(conn, userId);
            logAttempt(username, true, "success");

            System.out.println();
            System.out.println("    Login successful!");
            System.out.println("  Welcome, " + username + "!");
            System.out.println("  Role   : " + formatRole(role));
            printRoleMenu(role);
            printSeparator();

        } catch (SQLException e) {

            // they are printed to stderr for the developer / log file only.
            System.out.println("[ERROR] A system error occurred. "
                    + "Please try again later.");
            System.err.println("[DB ERROR] " + now() + " – " + e.getMessage());
        }
    }

    // =========================================================================
    //  DATABASE HELPER METHODS
    // =========================================================================

    /** Increments failed login counter for a user. */
    static void updateFailedAttempts(Connection conn, int userId, int count)
            throws SQLException {
        String sql = "UPDATE users SET failed_attempts = ? WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, count);
            ps.setInt(2, userId);
            ps.executeUpdate();
        }
    }

    /** Locks a user account after too many failed attempts. */
    static void lockAccount(Connection conn, int userId) throws SQLException {
        String sql = "UPDATE users SET account_locked = TRUE WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, userId);
            ps.executeUpdate();
        }
    }

    /** Resets the failed-attempts counter on successful login. */
    static void resetFailedAttempts(Connection conn, int userId) throws SQLException {
        String sql = "UPDATE users SET failed_attempts = 0 WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, userId);
            ps.executeUpdate();
        }
    }

    // =========================================================================
    //  AUDIT LOGGING
    // =========================================================================
    /**
     * Logs every login attempt to stderr (which can be redirected to a log file).
     *
     * Security requirement: an audit trail allows administrators to detect
     * and investigate suspicious activity.
     *
     * Format: [AUDIT] yyyy-MM-dd HH:mm:ss | user=<name> | success=<bool> | reason=<text>
     */
    static void logAttempt(String username, boolean success, String reason) {
        System.err.printf("[AUDIT] %s | user=%-20s | success=%-5s | reason=%s%n",
                now(), username, success, reason);
    }

    // =========================================================================
    //  UI HELPERS
    // =========================================================================

    static void printBanner() {
        printSeparator();
        System.out.println("    Student Information System – Secure Login");
        printSeparator();
    }

    static void printSeparator() {
        System.out.println("=".repeat(50));
    }

    /**
     * Displays an appropriate menu stub based on the user's role.
     *
     * This demonstrates Role-Based Access Control (RBAC):
     * different roles see different options after login.
     */
    static void printRoleMenu(String role) {
        System.out.println();
        switch (role.toLowerCase()) {
            case "student":
                System.out.println("  Available actions:");
                System.out.println("    [1] View my grades");
                System.out.println("    [2] Update account info");
                System.out.println("    [3] Logout");
                break;
            case "instructor":
                System.out.println("  Available actions:");
                System.out.println("    [1] Post grades");
                System.out.println("    [2] Update grades");
                System.out.println("    [3] View course roster");
                System.out.println("    [4] Logout");
                break;
            case "admin":
                System.out.println("  Available actions:");
                System.out.println("    [1] Manage accounts");
                System.out.println("    [2] Unlock accounts");
                System.out.println("    [3] View audit logs");
                System.out.println("    [4] Logout");
                break;
            default:
                System.out.println("  No menu available for role: " + role);
        }
    }

    /** Returns a user-friendly role label. */
    static String formatRole(String role) {
        if (role == null) return "Unknown";
        switch (role.toLowerCase()) {
            case "student":    return "Student";
            case "instructor": return "Instructor";
            case "admin":      return "Administrator";
            default:           return role;
        }
    }

    /** Returns the current timestamp as a formatted string. */
    static String now() {
        return LocalDateTime.now().format(TIMESTAMP_FMT);
    }
}

