# Password_Manager_application
The Secure Password Manager is a completely offline, desktop-based password management application built with Python.
It provides users with a secure way to store, manage, and retrieve their passwords for various services. The application uses advanced encryption techniques to ensure that all sensitive data remains protected, even if the database file is compromised. The entire application operates locally without any internet connection, making it ideal for users who prioritize privacy and security.

Security Architecture

The application employs a dual-layer security system. For user authentication, it uses SHA-256 hashing with unique salts for each user, ensuring that passwords are never stored in plain text. For data encryption, it utilizes the Fernet symmetric encryption protocol (which implements AES-128 in CBC mode with HMAC authentication) through the Python cryptography library. Each user's master password generates a unique encryption key using PBKDF2HMAC with 100,000 iterations, making brute-force attacks computationally expensive. The encryption salt is stored separately from the authentication salt, providing an additional layer of security.

User Registration and Recovery System

When a new user registers, they only need to provide a username and password. The application includes a built-in secure password generator that creates strong, random 16-character passwords combining lowercase letters, uppercase letters, digits, and special characters. Upon successful registration, the system generates 8 random recovery words from a predefined word list of 96 unique words. These recovery words serve as a backup authentication method - users must save them in the exact order they are presented. If a user forgets their master password, they can use the recovery key feature, which presents 8 dropdown combo boxes where they select the correct words in order. However, for security reasons, password recovery results in the deletion of all previously stored encrypted data, as the encryption key is derived from the original password.

Password Storage and Management

The main dashboard displays all stored passwords in a sortable table with columns for Title, Username, Password, and Description. Users can add new password entries through a dedicated form that includes fields for the service title, username/email, password, confirm password, and an optional description. The form provides convenient buttons for generating secure passwords, toggling password visibility, copying to clipboard, and pasting from clipboard. All data is encrypted before being stored in the SQLite database using the user's unique encryption key. When displaying passwords, the application decrypts them on-the-fly, showing the actual credentials to the user while maintaining encrypted storage.

Database Portability and Cross-System Usage

One of the key features of this application is database portability. Through the File menu, users can export their encrypted database file to any location on their system. This database file can then be imported on another computer running the same application. Since all encryption is based on the user's master password, the data remains secure during transfer. The application automatically detects and integrates the imported database, allowing users to access their passwords seamlessly across different systems or after operating system changes.

Data Integrity and Password Change Mechanism

The application includes a sophisticated password change mechanism that preserves all stored data. When a user changes their master password through the "Change Password" option, the system first verifies the current password, then decrypts all existing password entries using the old encryption key, re-encrypts them with a newly generated key derived from the new password, and updates the database accordingly. This process ensures zero data loss while maintaining security. The system also validates that the old encryption key works correctly before proceeding with any changes, preventing accidental data corruption.

User Interface and Usability Features

The graphical user interface is designed with simplicity and functionality in mind. The login screen provides a clean, centered form with options for login, registration, password recovery, and database import. All forms include clipboard integration - passwords can be copied from the generated field directly to the system clipboard and pasted into confirmation fields. The dashboard features a color-coded action bar with buttons for common operations like copying usernames, copying passwords, editing entries, and deleting entries. Confirmation dialogs are used for destructive actions to prevent accidental data loss. The application window is optimized at 500x500 pixels for authentication screens and expands to 700x600 for the main dashboard to accommodate the password table.

Technical Implementation Details

The application is structured into three main classes: EncryptionManager handles all cryptographic operations including key generation, encryption, and decryption; DatabaseManager manages SQLite database operations including user creation, password CRUD operations, and data import/export; and PasswordManagerApp orchestrates the user interface and application logic. The password generator uses Python's secrets module for cryptographically secure random generation. All database operations use parameterized queries to prevent SQL injection. The application handles exceptions gracefully with try-except blocks and provides user-friendly error messages through popup dialogs.

Offline Operation and Dependencies

The application requires only two external Python libraries: cryptography for encryption operations and tkinter for the graphical user interface (which comes pre-installed with Python on most systems). The SQLite database engine is built into Python's standard library, requiring no additional installation. Since the application operates entirely offline, there are no network requests, no cloud synchronization, and no external API calls. Users have complete control over their data, which resides solely in the local password_manager.db file. This design philosophy ensures maximum privacy and security while maintaining ease of use.
