# main.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import sqlite3
import os
import secrets
import string
import random
from datetime import datetime
import shutil
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from contextlib import contextmanager
from typing import Optional, Tuple, List, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ====================== CRYPTOGRAPHY MODULE ======================
class CryptoManager:
    """Handles all cryptographic operations with reusable functions."""
    
    @staticmethod
    def generate_data_key() -> bytes:
        """Generate a new random Data Encryption Key."""
        return Fernet.generate_key()
    
    @staticmethod
    def derive_password_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    @staticmethod
    def hash_sha256(data: str, salt: str) -> str:
        """Hash data using SHA256 with salt."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        hash_obj = hashlib.sha256(data + salt.encode('utf-8'))
        return hash_obj.hexdigest()
    
    @staticmethod
    def encrypt_with_key(plaintext: str, key: bytes) -> Optional[bytes]:
        """Encrypt data using Fernet symmetric encryption."""
        if not plaintext:
            return None
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        fernet = Fernet(key)
        return fernet.encrypt(plaintext)
    
    @staticmethod
    def decrypt_with_key(ciphertext: bytes, key: bytes) -> Optional[str]:
        """Decrypt data using Fernet symmetric encryption."""
        if not ciphertext:
            return ""
        try:
            fernet = Fernet(key)
            decrypted = fernet.decrypt(ciphertext)
            return decrypted.decode('utf-8')
        except InvalidToken:
            logger.error("Invalid token - decryption failed")
            return None
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None
    
    @staticmethod
    def validate_blob(encrypted_blob: bytes) -> bool:
        """Validate that a blob appears to be a valid Fernet token."""
        if not encrypted_blob:
            return False
        try:
            return len(encrypted_blob) > 32
        except Exception:
            return False


# ====================== DATABASE MANAGER ======================
class DatabaseManager:
    """Manages all database operations with proper context managers."""
    
    def __init__(self, db_path: str = "password_manager.db"):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database schema with migration support."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username_hash TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    recovery_key_hash TEXT,
                    salt TEXT NOT NULL,
                    encryption_salt BLOB NOT NULL,
                    encrypted_data_key BLOB,
                    encrypted_data_key_recovery BLOB
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    title_encrypted BLOB NOT NULL,
                    username_encrypted BLOB NOT NULL,
                    password_encrypted BLOB NOT NULL,
                    description_encrypted BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            self.migrate_database(cursor)
    
    def migrate_database(self, cursor):
        """Handle database schema migration for backward compatibility."""
        try:
            cursor.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'encrypted_data_key' not in columns:
                logger.info("Migrating database: Adding new columns")
                cursor.execute("ALTER TABLE users ADD COLUMN encrypted_data_key BLOB")
                cursor.execute("ALTER TABLE users ADD COLUMN encrypted_data_key_recovery BLOB")
                logger.info("Database migration completed")
        except Exception as e:
            logger.error(f"Migration error: {e}")
    
    def create_user(self, username: str, password: str, recovery_words: List[str]) -> Optional[int]:
        """Create new user with Data Encryption Key architecture."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            try:
                auth_salt = secrets.token_hex(16)
                encryption_salt = secrets.token_bytes(16)
                
                username_hash = CryptoManager.hash_sha256(username, auth_salt)
                password_hash = CryptoManager.hash_sha256(password, auth_salt)
                
                recovery_key = " ".join(recovery_words)
                recovery_hash = CryptoManager.hash_sha256(recovery_key, auth_salt)
                
                data_key = CryptoManager.generate_data_key()
                
                password_key = CryptoManager.derive_password_key(password, encryption_salt)
                recovery_key_derived = CryptoManager.derive_password_key(recovery_key, encryption_salt)
                
                encrypted_data_key = CryptoManager.encrypt_with_key(data_key.decode(), password_key)
                encrypted_data_key_recovery = CryptoManager.encrypt_with_key(data_key.decode(), recovery_key_derived)
                
                cursor.execute('''
                    INSERT INTO users (
                        username_hash, password_hash, recovery_key_hash, 
                        salt, encryption_salt, encrypted_data_key, encrypted_data_key_recovery
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (username_hash, password_hash, recovery_hash, 
                      auth_salt, encryption_salt, encrypted_data_key, encrypted_data_key_recovery))
                
                return cursor.lastrowid
                
            except sqlite3.IntegrityError:
                logger.warning(f"Username already exists: {username}")
                return None
            except Exception as e:
                logger.error(f"Error creating user: {e}")
                return None
    
    def verify_login(self, username: str, password: str) -> Tuple[Optional[int], Optional[bytes]]:
        """Verify login and return user_id and Data Key."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, password_hash, salt, encryption_salt, encrypted_data_key 
                FROM users
            ''')
            users = cursor.fetchall()
            
            for user in users:
                user_id = user['id']
                stored_password_hash = user['password_hash']
                auth_salt = user['salt']
                encryption_salt = user['encryption_salt']
                encrypted_data_key = user['encrypted_data_key']
                
                input_password_hash = CryptoManager.hash_sha256(password, auth_salt)
                if input_password_hash == stored_password_hash:
                    cursor.execute('SELECT username_hash FROM users WHERE id = ?', (user_id,))
                    stored_username_hash = cursor.fetchone()['username_hash']
                    
                    input_username_hash = CryptoManager.hash_sha256(username, auth_salt)
                    if input_username_hash == stored_username_hash:
                        if not encrypted_data_key:
                            data_key = self.migrate_user_to_new_architecture(
                                user_id, password, encryption_salt, auth_salt
                            )
                            return (user_id, data_key) if data_key else (None, None)
                        
                        password_key = CryptoManager.derive_password_key(password, encryption_salt)
                        data_key_str = CryptoManager.decrypt_with_key(encrypted_data_key, password_key)
                        
                        if data_key_str:
                            return user_id, data_key_str.encode()
            
            return None, None
    
    def migrate_user_to_new_architecture(self, user_id: int, password: str, 
                                         encryption_salt: bytes, auth_salt: str) -> Optional[bytes]:
        """Migrate existing user to new DEK architecture."""
        logger.info(f"Migrating user {user_id} to new architecture")
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            try:
                data_key = CryptoManager.generate_data_key()
                password_key = CryptoManager.derive_password_key(password, encryption_salt)
                old_encryption_key = password_key
                
                cursor.execute('''
                    SELECT id, title_encrypted, username_encrypted, 
                           password_encrypted, description_encrypted 
                    FROM passwords WHERE user_id = ?
                ''', (user_id,))
                
                old_passwords = cursor.fetchall()
                
                for pwd in old_passwords:
                    try:
                        title = CryptoManager.decrypt_with_key(pwd['title_encrypted'], old_encryption_key)
                        username = CryptoManager.decrypt_with_key(pwd['username_encrypted'], old_encryption_key)
                        password = CryptoManager.decrypt_with_key(pwd['password_encrypted'], old_encryption_key)
                        description = CryptoManager.decrypt_with_key(pwd['description_encrypted'], old_encryption_key) if pwd['description_encrypted'] else ""
                        
                        if not all([title, username, password]):
                            logger.warning(f"Skipping corrupted entry {pwd['id']}")
                            continue
                        
                        new_title = CryptoManager.encrypt_with_key(title, data_key)
                        new_username = CryptoManager.encrypt_with_key(username, data_key)
                        new_password = CryptoManager.encrypt_with_key(password, data_key)
                        new_description = CryptoManager.encrypt_with_key(description, data_key) if description else None
                        
                        cursor.execute('''
                            UPDATE passwords 
                            SET title_encrypted = ?, username_encrypted = ?, 
                                password_encrypted = ?, description_encrypted = ?
                            WHERE id = ?
                        ''', (new_title, new_username, new_password, new_description, pwd['id']))
                        
                    except Exception as e:
                        logger.error(f"Error migrating password entry {pwd['id']}: {e}")
                        continue
                
                encrypted_data_key = CryptoManager.encrypt_with_key(data_key.decode(), password_key)
                encrypted_data_key_recovery = encrypted_data_key
                
                cursor.execute('''
                    UPDATE users 
                    SET encrypted_data_key = ?, encrypted_data_key_recovery = ?
                    WHERE id = ?
                ''', (encrypted_data_key, encrypted_data_key_recovery, user_id))
                
                logger.info(f"User {user_id} migration completed")
                return data_key
                
            except Exception as e:
                logger.error(f"Migration failed for user {user_id}: {e}")
                return None
    
    def verify_recovery_key(self, username: str, recovery_words: List[str]) -> Tuple[Optional[int], Optional[bytes]]:
        """Verify recovery key and return user_id and Data Key."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            recovery_key = " ".join(recovery_words)
            
            cursor.execute('''
                SELECT id, recovery_key_hash, salt, encryption_salt, 
                       encrypted_data_key_recovery 
                FROM users
            ''')
            users = cursor.fetchall()
            
            for user in users:
                user_id = user['id']
                stored_recovery_hash = user['recovery_key_hash']
                auth_salt = user['salt']
                encryption_salt = user['encryption_salt']
                encrypted_data_key_recovery = user['encrypted_data_key_recovery']
                
                input_recovery_hash = CryptoManager.hash_sha256(recovery_key, auth_salt)
                if input_recovery_hash == stored_recovery_hash:
                    cursor.execute('SELECT username_hash FROM users WHERE id = ?', (user_id,))
                    stored_username_hash = cursor.fetchone()['username_hash']
                    
                    input_username_hash = CryptoManager.hash_sha256(username, auth_salt)
                    if input_username_hash == stored_username_hash:
                        if encrypted_data_key_recovery:
                            recovery_key_derived = CryptoManager.derive_password_key(recovery_key, encryption_salt)
                            data_key_str = CryptoManager.decrypt_with_key(
                                encrypted_data_key_recovery, recovery_key_derived
                            )
                            if data_key_str:
                                return user_id, data_key_str.encode()
                
            return None, None
    
    def update_password_with_data_key(self, user_id: int, new_password: str, data_key: bytes):
        """Update password without re-encrypting all records."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT salt, encryption_salt FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            auth_salt = user['salt']
            encryption_salt = user['encryption_salt']
            
            new_password_hash = CryptoManager.hash_sha256(new_password, auth_salt)
            new_password_key = CryptoManager.derive_password_key(new_password, encryption_salt)
            new_encrypted_data_key = CryptoManager.encrypt_with_key(data_key.decode(), new_password_key)
            
            cursor.execute('''
                UPDATE users 
                SET password_hash = ?, encrypted_data_key = ?
                WHERE id = ?
            ''', (new_password_hash, new_encrypted_data_key, user_id))
    
    def recovery_update_password(self, user_id: int, new_password: str, data_key: bytes):
        """Update password after recovery - preserves all data."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT salt, encryption_salt FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            auth_salt = user['salt']
            encryption_salt = user['encryption_salt']
            
            new_password_hash = CryptoManager.hash_sha256(new_password, auth_salt)
            new_password_key = CryptoManager.derive_password_key(new_password, encryption_salt)
            new_encrypted_data_key = CryptoManager.encrypt_with_key(data_key.decode(), new_password_key)
            
            cursor.execute('''
                UPDATE users 
                SET password_hash = ?, encrypted_data_key = ?
                WHERE id = ?
            ''', (new_password_hash, new_encrypted_data_key, user_id))
    
    def add_password(self, user_id: int, data_key: bytes, title: str, 
                    username: str, password: str, description: str = "") -> bool:
        """Add a new password entry encrypted with Data Key."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            try:
                title_encrypted = CryptoManager.encrypt_with_key(title, data_key)
                username_encrypted = CryptoManager.encrypt_with_key(username, data_key)
                password_encrypted = CryptoManager.encrypt_with_key(password, data_key)
                description_encrypted = CryptoManager.encrypt_with_key(description, data_key) if description else None
                
                cursor.execute('''
                    INSERT INTO passwords (user_id, title_encrypted, username_encrypted, 
                                         password_encrypted, description_encrypted)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, title_encrypted, username_encrypted, 
                      password_encrypted, description_encrypted))
                
                return True
            except Exception as e:
                logger.error(f"Error adding password: {e}")
                return False
    
    def get_passwords(self, user_id: int, data_key: bytes) -> List[Tuple[int, str, str, str, str]]:
        """Retrieve and decrypt all passwords for a user."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, title_encrypted, username_encrypted, 
                       password_encrypted, description_encrypted
                FROM passwords WHERE user_id = ?
            ''', (user_id,))
            
            encrypted_passwords = cursor.fetchall()
        
        decrypted_passwords = []
        for pwd in encrypted_passwords:
            try:
                if not all([CryptoManager.validate_blob(pwd['title_encrypted']),
                           CryptoManager.validate_blob(pwd['username_encrypted']),
                           CryptoManager.validate_blob(pwd['password_encrypted'])]):
                    logger.warning(f"Invalid blob detected for entry {pwd['id']}, skipping")
                    continue
                
                title = CryptoManager.decrypt_with_key(pwd['title_encrypted'], data_key)
                username = CryptoManager.decrypt_with_key(pwd['username_encrypted'], data_key)
                password = CryptoManager.decrypt_with_key(pwd['password_encrypted'], data_key)
                description = CryptoManager.decrypt_with_key(pwd['description_encrypted'], data_key) if pwd['description_encrypted'] else ""
                
                if all([title, username, password]):
                    decrypted_passwords.append((pwd['id'], title, username, password, description))
                else:
                    logger.warning(f"Failed to decrypt entry {pwd['id']}, skipping")
                    
            except Exception as e:
                logger.error(f"Error processing password entry {pwd['id']}: {e}")
                continue
        
        return decrypted_passwords
    
    def update_password_entry(self, entry_id: int, data_key: bytes, title: str,
                            username: str, password: str, description: str) -> bool:
        """Update an existing password entry."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            try:
                title_encrypted = CryptoManager.encrypt_with_key(title, data_key)
                username_encrypted = CryptoManager.encrypt_with_key(username, data_key)
                password_encrypted = CryptoManager.encrypt_with_key(password, data_key)
                description_encrypted = CryptoManager.encrypt_with_key(description, data_key) if description else None
                
                cursor.execute('''
                    UPDATE passwords 
                    SET title_encrypted = ?, username_encrypted = ?, 
                        password_encrypted = ?, description_encrypted = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (title_encrypted, username_encrypted, password_encrypted,
                      description_encrypted, entry_id))
                
                return True
            except Exception as e:
                logger.error(f"Error updating password entry {entry_id}: {e}")
                return False
    
    def delete_password(self, entry_id: int):
        """Delete a password entry."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))
    
    def export_database(self, export_path: str):
        """Export database to file."""
        shutil.copy2(self.db_path, export_path)
    
    def import_database(self, import_path: str):
        """Import database from file."""
        shutil.copy2(import_path, self.db_path)
        self.init_database()


# ====================== PASSWORD GENERATOR ======================
class PasswordGenerator:
    """Generates secure passwords and recovery phrases."""
    
    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generate a cryptographically secure random password."""
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        all_chars = lowercase + uppercase + digits + special
        
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        random.shuffle(password)
        return ''.join(password)
    
    @staticmethod
    def generate_recovery_words() -> List[str]:
        """Generate 8 random recovery words."""
        word_list = [
            "apple", "bridge", "castle", "dragon", "eagle", "forest", "garden", "harbor",
            "island", "jungle", "knight", "lemon", "mountain", "night", "ocean", "panda",
            "queen", "river", "storm", "tiger", "umbrella", "valley", "whale", "xenon",
            "yellow", "zebra", "anchor", "butterfly", "crystal", "diamond", "emerald",
            "falcon", "galaxy", "horizon", "ivory", "jasmine", "koala", "lantern",
            "meteor", "nebula", "orchid", "phoenix", "quartz", "rainbow", "sapphire",
            "thunder", "unicorn", "violet", "willow", "zenith", "aurora", "blizzard",
            "comet", "dolphin", "eclipse", "flame", "glacier", "harmony", "infinity",
            "journey", "kingdom", "liberty", "miracle", "nectar", "oasis", "paradise",
            "quest", "relic", "serenity", "temple", "utopia", "victory", "wisdom",
            "adventure", "beacon", "cascade", "destiny", "enchant", "fortune", "guardian",
            "haven", "inspire", "jubilee", "keystone", "legend", "mystic", "noble",
            "oracle", "pioneer", "radiant", "spirit", "tranquil", "unity", "venture",
            "whisper", "wonder", "harmony", "balance", "courage", "dream", "eternity",
            "freedom", "genesis", "hope", "imagine", "joyful", "kindred", "luminous"
        ]
        
        return random.sample(word_list, 8)
    
    @staticmethod
    def get_all_words() -> List[str]:
        """Get sorted list of all possible recovery words."""
        return sorted([
            "apple", "bridge", "castle", "dragon", "eagle", "forest", "garden", "harbor",
            "island", "jungle", "knight", "lemon", "mountain", "night", "ocean", "panda",
            "queen", "river", "storm", "tiger", "umbrella", "valley", "whale", "xenon",
            "yellow", "zebra", "anchor", "butterfly", "crystal", "diamond", "emerald",
            "falcon", "galaxy", "horizon", "ivory", "jasmine", "koala", "lantern",
            "meteor", "nebula", "orchid", "phoenix", "quartz", "rainbow", "sapphire",
            "thunder", "unicorn", "violet", "willow", "zenith", "aurora", "blizzard",
            "comet", "dolphin", "eclipse", "flame", "glacier", "harmony", "infinity",
            "journey", "kingdom", "liberty", "miracle", "nectar", "oasis", "paradise",
            "quest", "relic", "serenity", "temple", "utopia", "victory", "wisdom",
            "adventure", "beacon", "cascade", "destiny", "enchant", "fortune", "guardian",
            "haven", "inspire", "jubilee", "keystone", "legend", "mystic", "noble",
            "oracle", "pioneer", "radiant", "spirit", "tranquil", "unity", "venture",
            "whisper", "wonder", "harmony", "balance", "courage", "dream", "eternity",
            "freedom", "genesis", "hope", "imagine", "joyful", "kindred", "luminous"
        ])


# ====================== MAIN APPLICATION ======================
class PasswordManagerApp:
    """Main application GUI class with DEK architecture."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager v2.0 - DEK Architecture")
        self.root.geometry("500x500")
        self.root.resizable(False, False)
        self.root.configure(bg='#f0f0f0')
        
        self.db = DatabaseManager()
        self.current_user_id = None
        self.current_username = None
        self.data_key = None  # Data Encryption Key
        
        self.colors = {
            'primary': '#2c3e50',
            'secondary': '#3498db',
            'success': '#27ae60',
            'danger': '#e74c3c',
            'warning': '#f39c12',
            'light': '#ecf0f1',
            'dark': '#2c3e50',
            'white': '#ffffff',
            'bg': '#f5f6fa'
        }
        
        self.show_login_screen()
    
    def clear_screen(self):
        """Remove all widgets from the root window."""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def create_styled_button(self, parent, text, command, color, width=20, height=1):
        """Create a styled button with consistent appearance."""
        return tk.Button(parent, text=text, command=command,
                        bg=color, fg='white', font=('Arial', 10, 'bold'),
                        width=width, height=height, bd=0, padx=10, pady=8,
                        cursor='hand2',
                        activebackground=color, activeforeground='white')
    
    def show_login_screen(self):
        """Display the login screen."""
        self.clear_screen()
        self.root.geometry("500x500")
        self.root.resizable(False, False)
        
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(expand=True, fill='both', padx=30, pady=30)
        
        tk.Label(main_frame, text="🔐 Password Manager v2.0", 
                font=('Arial', 18, 'bold'),
                bg=self.colors['bg'],
                fg=self.colors['primary']).pack(pady=(20, 10))
        
        tk.Label(main_frame, text="DEK Architecture - Data Survives Recovery", 
                font=('Arial', 9, 'italic'),
                bg=self.colors['bg'],
                fg='gray').pack(pady=(0, 20))
        
        form_frame = tk.Frame(main_frame, bg='white', relief='flat', bd=0)
        form_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(form_frame, text="👤 Username:", bg='white',
                font=('Arial', 10)).pack(pady=(15, 5))
        self.login_username = tk.Entry(form_frame, font=('Arial', 11), width=30, bd=1, relief='solid')
        self.login_username.pack(pady=(0, 10), ipady=3)
        
        tk.Label(form_frame, text="🔑 Master Password:", bg='white',
                font=('Arial', 10)).pack(pady=(5, 5))
        self.login_password = tk.Entry(form_frame, show="*", font=('Arial', 11), width=30, bd=1, relief='solid')
        self.login_password.pack(pady=(0, 20), ipady=3)
        
        self.create_styled_button(form_frame, "Login", self.login, self.colors['secondary']).pack(pady=5)
        self.create_styled_button(form_frame, "Create Account", self.show_register_screen, self.colors['success']).pack(pady=5)
        
        tk.Button(form_frame, text="Forgot Password? (Recovery)",
                 command=self.show_recovery_screen,
                 bg='white', fg=self.colors['secondary'],
                 font=('Arial', 9, 'underline'), bd=0, cursor='hand2').pack(pady=(10, 5))
        
        tk.Button(form_frame, text="Import Database",
                 command=self.import_database,
                 bg='white', fg=self.colors['warning'],
                 font=('Arial', 9, 'underline'), bd=0, cursor='hand2').pack(pady=(0, 10))
    
    def show_register_screen(self):
        """Display the registration screen."""
        self.clear_screen()
        self.root.geometry("500x500")
        
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        tk.Label(main_frame, text="Create Account", font=('Arial', 16, 'bold'),
                bg=self.colors['bg'], fg=self.colors['primary']).pack(pady=(10, 20))
        
        form_frame = tk.Frame(main_frame, bg='white')
        form_frame.pack(pady=5, padx=15, fill='x')
        
        tk.Label(form_frame, text="👤 Username:", bg='white',
                font=('Arial', 10)).pack(pady=(10, 5))
        self.reg_username = tk.Entry(form_frame, font=('Arial', 11), width=35, bd=1, relief='solid')
        self.reg_username.pack(pady=(0, 10), ipady=2)
        
        tk.Label(form_frame, text="🔑 Master Password:", bg='white',
                font=('Arial', 10)).pack(pady=(5, 5))
        self.reg_password = tk.Entry(form_frame, show="*", font=('Arial', 11), width=35, bd=1, relief='solid')
        self.reg_password.pack(pady=(0, 5), ipady=2)
        
        pwd_btn_frame = tk.Frame(form_frame, bg='white')
        pwd_btn_frame.pack(pady=(0, 10))
        
        self.create_styled_button(pwd_btn_frame, "Generate Password", 
                                 self.generate_and_show_password, 
                                 self.colors['secondary'], width=15).pack(side='left', padx=3)
        
        self.create_styled_button(pwd_btn_frame, "Show/Hide", 
                                 self.toggle_reg_password, 
                                 self.colors['warning'], width=10).pack(side='left', padx=3)
        
        self.create_styled_button(pwd_btn_frame, "Copy", 
                                 self.copy_reg_password, 
                                 self.colors['success'], width=8).pack(side='left', padx=3)
        
        tk.Label(form_frame, text="🔑 Confirm Password:", bg='white',
                font=('Arial', 10)).pack(pady=(5, 5))
        self.reg_confirm_password = tk.Entry(form_frame, show="*", font=('Arial', 11), width=35, bd=1, relief='solid')
        self.reg_confirm_password.pack(pady=(0, 5), ipady=2)
        
        self.create_styled_button(form_frame, "Paste from Clipboard", 
                                 self.paste_to_confirm, 
                                 self.colors['secondary'], width=20).pack(pady=(0, 10))
        
        self.create_styled_button(form_frame, "✅ Confirm & Register", 
                                 self.register_user, 
                                 self.colors['success'], width=25, height=2).pack(pady=10)
        
        self.create_styled_button(form_frame, "← Back to Login", 
                                 self.show_login_screen, 
                                 self.colors['danger'], width=25).pack(pady=5)
    
    def show_recovery_screen(self):
        """Display the password recovery screen."""
        self.clear_screen()
        self.root.geometry("500x600")
        
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        tk.Label(main_frame, text="Password Recovery", font=('Arial', 16, 'bold'),
                bg=self.colors['bg'], fg=self.colors['primary']).pack(pady=(10, 5))
        
        tk.Label(main_frame, text="✅ Your data will be preserved!", 
                font=('Arial', 9, 'italic'),
                bg=self.colors['bg'], fg=self.colors['success']).pack(pady=(0, 15))
        
        form_frame = tk.Frame(main_frame, bg='white')
        form_frame.pack(pady=5, padx=15, fill='x')
        
        tk.Label(form_frame, text="Select recovery words in correct order:",
                bg='white', font=('Arial', 9, 'italic'), fg='gray').pack(pady=(10, 5))
        
        tk.Label(form_frame, text="👤 Username:", bg='white',
                font=('Arial', 10)).pack(pady=(5, 5))
        self.recovery_username = tk.Entry(form_frame, font=('Arial', 11), width=35, bd=1, relief='solid')
        self.recovery_username.pack(pady=(0, 10), ipady=2)
        
        all_words = PasswordGenerator.get_all_words()
        
        self.recovery_combos = []
        for i in range(8):
            frame = tk.Frame(form_frame, bg='white')
            frame.pack(pady=2)
            
            tk.Label(frame, text=f"Word {i+1}:", bg='white',
                    font=('Arial', 9), width=8, anchor='w').pack(side='left', padx=(0, 5))
            
            combo = ttk.Combobox(frame, values=all_words, width=25, state='readonly')
            combo.pack(side='left')
            combo.set(f"Select word {i+1}...")
            self.recovery_combos.append(combo)
        
        tk.Label(form_frame, text="🔑 New Master Password:", bg='white',
                font=('Arial', 10)).pack(pady=(10, 5))
        self.recovery_new_password = tk.Entry(form_frame, show="*", font=('Arial', 11), 
                                              width=35, bd=1, relief='solid')
        self.recovery_new_password.pack(pady=(0, 10), ipady=2)
        
        tk.Label(form_frame, 
                text="✅ Your stored passwords will NOT be deleted!",
                bg='white', fg=self.colors['success'],
                font=('Arial', 8, 'bold')).pack(pady=5)
        
        self.create_styled_button(form_frame, "✅ Recover Password (Preserve Data)", 
                                 self.recover_password, 
                                 self.colors['warning'], width=30, height=2).pack(pady=15)
        
        self.create_styled_button(form_frame, "← Back to Login", 
                                 self.show_login_screen, 
                                 self.colors['danger'], width=25).pack(pady=5)
    
    def show_main_dashboard(self):
        """Display the main password management dashboard."""
        self.clear_screen()
        self.root.geometry("700x600")
        self.root.resizable(True, True)
        
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Database", command=self.export_database)
        file_menu.add_command(label="Import Database", command=self.import_database)
        file_menu.add_separator()
        file_menu.add_command(label="Change Master Password", command=self.show_change_password)
        file_menu.add_command(label="Logout", command=self.logout)
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(expand=True, fill='both', padx=15, pady=15)
        
        header_frame = tk.Frame(main_frame, bg=self.colors['primary'])
        header_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(header_frame, text=f"👋 Welcome, {self.current_username}",
                font=('Arial', 12, 'bold'), bg=self.colors['primary'],
                fg='white').pack(side='left', padx=15, pady=10)
        
        self.create_styled_button(header_frame, "➕ Add Password", 
                                 lambda: self.show_add_password(),
                                 self.colors['success'], width=15).pack(side='right', padx=15, pady=8)
        
        list_frame = tk.Frame(main_frame, bg='white', relief='solid', bd=1)
        list_frame.pack(fill='both', expand=True)
        
        columns = ('Title', 'Username', 'Password', 'Description')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=12)
        
        col_widths = [150, 150, 150, 200]
        for col, width in zip(columns, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, minwidth=100)
        
        self.tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        btn_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        btn_frame.pack(fill='x', pady=10)
        
        self.create_styled_button(btn_frame, "Copy Username", self.copy_username,
                                 self.colors['secondary'], width=15).pack(side='left', padx=3)
        
        self.create_styled_button(btn_frame, "Copy Password", self.copy_password,
                                 self.colors['secondary'], width=15).pack(side='left', padx=3)
        
        self.create_styled_button(btn_frame, "Edit", self.show_edit_password,
                                 self.colors['warning'], width=10).pack(side='left', padx=3)
        
        self.create_styled_button(btn_frame, "Delete", self.delete_password,
                                 self.colors['danger'], width=10).pack(side='left', padx=3)
        
        self.load_passwords()
    
    def show_add_password(self, edit_mode=False):
        """Show dialog for adding or editing a password entry."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Password" if not edit_mode else "Edit Password")
        dialog.geometry("450x600")
        dialog.configure(bg=self.colors['bg'])
        dialog.resizable(False, False)
        
        current_title = ""
        current_username = ""
        current_password = ""
        current_description = ""
        entry_id = None
        
        if edit_mode:
            selection = self.tree.selection()
            if selection:
                item = self.tree.item(selection[0])
                current_title = item['values'][0]
                current_username = item['values'][1]
                current_password = item['values'][2]
                current_description = item['values'][3]
                entry_id = item['tags'][0] if item['tags'] else None
        
        main_frame = tk.Frame(dialog, bg='white', relief='solid', bd=1)
        main_frame.pack(expand=True, fill='both', padx=15, pady=15)
        
        # Title
        tk.Label(main_frame, text="📌 Title:", bg='white', 
                font=('Arial', 10, 'bold')).pack(pady=(15, 5))
        title_entry = tk.Entry(main_frame, font=('Arial', 11), width=40, bd=1, relief='solid')
        title_entry.insert(0, current_title)
        title_entry.pack(pady=(0, 10), ipady=2)
        
        # Username
        tk.Label(main_frame, text="👤 Username:", bg='white', 
                font=('Arial', 10, 'bold')).pack(pady=(5, 5))
        username_entry = tk.Entry(main_frame, font=('Arial', 11), width=40, bd=1, relief='solid')
        username_entry.insert(0, current_username)
        username_entry.pack(pady=(0, 10), ipady=2)
        
        # Password
        tk.Label(main_frame, text="🔑 Password:", bg='white', 
                font=('Arial', 10, 'bold')).pack(pady=(5, 5))
        password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11), width=40, bd=1, relief='solid')
        password_entry.insert(0, current_password)
        password_entry.pack(pady=(0, 5), ipady=2)
        
        pwd_btn_frame = tk.Frame(main_frame, bg='white')
        pwd_btn_frame.pack(pady=(0, 5))
        
        def toggle_password_visibility():
            if password_entry.cget('show') == '*':
                password_entry.config(show='')
            else:
                password_entry.config(show='*')
        
        self.create_styled_button(pwd_btn_frame, "👁 Show/Hide", toggle_password_visibility,
                                 self.colors['warning'], width=12).pack(side='left', padx=3)
        
        self.create_styled_button(pwd_btn_frame, "🎲 Generate", 
                                 lambda: [password_entry.delete(0, tk.END), 
                                        password_entry.insert(0, PasswordGenerator.generate_secure_password()),
                                        password_entry.config(show='')],
                                 self.colors['secondary'], width=12).pack(side='left', padx=3)
        
        self.create_styled_button(pwd_btn_frame, "📋 Copy", 
                                 lambda: [self.root.clipboard_clear(), 
                                         self.root.clipboard_append(password_entry.get()),
                                         messagebox.showinfo("Copied", "Password copied to clipboard!")] 
                                 if password_entry.get() else messagebox.showwarning("Warning", "No password to copy!"),
                                 self.colors['success'], width=10).pack(side='left', padx=3)
        
        # Confirm Password
        tk.Label(main_frame, text="🔑 Confirm Password:", bg='white', 
                font=('Arial', 10, 'bold')).pack(pady=(10, 5))
        confirm_password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11), width=40, bd=1, relief='solid')
        confirm_password_entry.insert(0, current_password)
        confirm_password_entry.pack(pady=(0, 5), ipady=2)
        
        confirm_btn_frame = tk.Frame(main_frame, bg='white')
        confirm_btn_frame.pack(pady=(0, 10))
        
        def toggle_confirm_visibility():
            if confirm_password_entry.cget('show') == '*':
                confirm_password_entry.config(show='')
            else:
                confirm_password_entry.config(show='*')
        
        self.create_styled_button(confirm_btn_frame, "👁 Show/Hide", toggle_confirm_visibility,
                                 self.colors['warning'], width=12).pack(side='left', padx=3)
        
        self.create_styled_button(confirm_btn_frame, "📋 Paste", 
                                 lambda: [confirm_password_entry.delete(0, tk.END),
                                         confirm_password_entry.insert(0, self.root.clipboard_get()),
                                         messagebox.showinfo("Pasted", "Password pasted from clipboard!")]
                                 if self.root.clipboard_get() else messagebox.showwarning("Warning", "Clipboard is empty!"),
                                 self.colors['secondary'], width=12).pack(side='left', padx=3)
        
        # Description
        tk.Label(main_frame, text="📝 Description:", bg='white', 
                font=('Arial', 10, 'bold')).pack(pady=(5, 5))
        description_text = tk.Text(main_frame, font=('Arial', 11), width=40, height=3, bd=1, relief='solid')
        description_text.insert('1.0', current_description)
        description_text.pack(pady=(0, 10))
        
        # Save function using Data Encryption Key (DEK)
        def save_password():
            title = title_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            confirm_password = confirm_password_entry.get().strip()
            description = description_text.get('1.0', 'end-1c').strip()
            
            if not title or not username or not password:
                messagebox.showwarning("⚠️ Warning", "Title, username and password are required!")
                return
            
            if password != confirm_password:
                messagebox.showerror("❌ Error", "Passwords do not match!\nPlease check the Confirm Password field.")
                return
            
            if not self.data_key:
                messagebox.showerror("❌ Error", "Encryption key not available. Please login again.")
                return
            
            try:
                if edit_mode and entry_id:
                    success = self.db.update_password_entry(
                        int(entry_id), self.data_key, title, username, password, description
                    )
                    if success:
                        messagebox.showinfo("✅ Success", "Password updated successfully!")
                        self.load_passwords()
                        dialog.destroy()
                    else:
                        messagebox.showerror("❌ Error", "Failed to update password. Please try again.")
                else:
                    success = self.db.add_password(
                        self.current_user_id, self.data_key, title, username, password, description
                    )
                    if success:
                        messagebox.showinfo("✅ Success", "Password saved to database!")
                        self.load_passwords()
                        dialog.destroy()
                    else:
                        messagebox.showerror("❌ Error", "Failed to save password. Please try again.")
            except Exception as e:
                messagebox.showerror("❌ Error", f"An error occurred: {str(e)}")
                logger.error(f"Error in save_password: {e}")
        
        # Buttons
        btn_frame = tk.Frame(main_frame, bg='white')
        btn_frame.pack(pady=15)
        
        self.create_styled_button(btn_frame, "💾 SAVE TO DATABASE", save_password,
                                 self.colors['success'], width=20, height=2).pack(side='left', padx=5)
        
        self.create_styled_button(btn_frame, "❌ Cancel", dialog.destroy,
                                 self.colors['danger'], width=15, height=2).pack(side='left', padx=5)
    
    def show_edit_password(self):
        """Show dialog for editing selected password."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("⚠️ Warning", "Please select an entry to edit!")
            return
        self.show_add_password(edit_mode=True)
    
    def show_change_password(self):
        """Show dialog for changing master password."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Master Password")
        dialog.geometry("420x400")
        dialog.configure(bg='#2c3e50')
        dialog.resizable(False, False)
        
        main_frame = tk.Frame(dialog, bg='white', relief='flat', bd=0)
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        tk.Label(main_frame, text="🔑 Change Master Password", font=('Arial', 14, 'bold'),
                bg='white', fg='#2c3e50').pack(pady=15)
        
        tk.Label(main_frame, text="✅ Only the Data Key will be re-encrypted\nNo password entries will be modified",
                bg='white', fg='#27ae60', font=('Arial', 9)).pack()
        
        tk.Label(main_frame, text="Current Password:", bg='white', 
                font=('Arial', 10, 'bold')).pack(pady=(15, 5))
        old_password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11), bd=2, relief='solid')
        old_password_entry.pack(fill='x', ipady=5, padx=20)
        
        tk.Label(main_frame, text="New Password:", bg='white', 
                font=('Arial', 10, 'bold')).pack(pady=(10, 5))
        new_password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11), bd=2, relief='solid')
        new_password_entry.pack(fill='x', ipady=5, padx=20)
        
        tk.Label(main_frame, text="Confirm New Password:", bg='white', 
                font=('Arial', 10, 'bold')).pack(pady=(10, 5))
        confirm_new_password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11), bd=2, relief='solid')
        confirm_new_password_entry.pack(fill='x', ipady=5, padx=20)
        
        def change_password():
            old_password = old_password_entry.get().strip()
            new_password = new_password_entry.get().strip()
            confirm_new = confirm_new_password_entry.get().strip()
            
            if not old_password or not new_password or not confirm_new:
                messagebox.showwarning("⚠️ Warning", "All fields are required!")
                return
            
            if new_password != confirm_new:
                messagebox.showerror("❌ Error", "New passwords don't match!")
                return
            
            if old_password == new_password:
                messagebox.showwarning("⚠️ Warning", "New password is same as current!")
                return
            
            try:
                user_id, data_key = self.db.verify_login(self.current_username, old_password)
                
                if user_id and data_key:
                    self.db.update_password_with_data_key(user_id, new_password, data_key)
                    self.data_key = data_key
                    messagebox.showinfo("✅ Success", 
                                      "Master password changed successfully!\n\n"
                                      "📊 No password entries were modified.\n"
                                      "🔐 Only the Data Key was re-encrypted.")
                    dialog.destroy()
                    self.load_passwords()
                else:
                    messagebox.showerror("❌ Error", "Current password is incorrect!")
            except Exception as e:
                messagebox.showerror("❌ Error", f"Failed to change password: {str(e)}")
        
        tk.Button(main_frame, text="✅ Change Password",
                 command=change_password,
                 bg='#27ae60', fg='white', font=('Arial', 12, 'bold'),
                 bd=0, padx=20, pady=12, cursor='hand2',
                 activebackground='#219a52', activeforeground='white').pack(fill='x', pady=(25, 10), padx=20)
        
        tk.Button(main_frame, text="❌ Cancel",
                 command=dialog.destroy,
                 bg='#e74c3c', fg='white', font=('Arial', 11, 'bold'),
                 bd=0, padx=20, pady=10, cursor='hand2',
                 activebackground='#c0392b', activeforeground='white').pack(fill='x', padx=20)
    
    def delete_password(self):
        """Delete selected password entry."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("⚠️ Warning", "Please select an entry to delete!")
            return
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            item = self.tree.item(selection[0])
            entry_id = item['tags'][0] if item['tags'] else None
            
            if entry_id:
                self.db.delete_password(int(entry_id))
                self.load_passwords()
                messagebox.showinfo("✅ Success", "Entry deleted!")
    
    def copy_username(self):
        """Copy selected username to clipboard."""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            username = item['values'][1]
            self.root.clipboard_clear()
            self.root.clipboard_append(username)
            messagebox.showinfo("📋 Copied", "Username copied to clipboard!")
    
    def copy_password(self):
        """Copy selected password to clipboard."""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            password = item['values'][2]
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("📋 Copied", "Password copied to clipboard!")
    
    def generate_and_show_password(self):
        """Generate password and show in registration form."""
        password = PasswordGenerator.generate_secure_password()
        self.reg_password.delete(0, tk.END)
        self.reg_password.insert(0, password)
        self.reg_password.config(show='')
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("✅ Password Generated", 
                          "Strong password generated!\n\n"
                          "• Visible in password field\n"
                          "• Copied to clipboard")
    
    def toggle_reg_password(self):
        """Toggle password visibility in registration."""
        if self.reg_password.cget('show') == '*':
            self.reg_password.config(show='')
        else:
            self.reg_password.config(show='*')
    
    def copy_reg_password(self):
        """Copy registration password to clipboard."""
        password = self.reg_password.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("📋 Copied", "Password copied to clipboard!")
    
    def paste_to_confirm(self):
        """Paste clipboard content to confirm password field."""
        try:
            clipboard_text = self.root.clipboard_get()
            self.reg_confirm_password.delete(0, tk.END)
            self.reg_confirm_password.insert(0, clipboard_text)
            messagebox.showinfo("📋 Pasted", "Pasted from clipboard!")
        except:
            messagebox.showwarning("⚠️ Warning", "Clipboard is empty!")
    
    def register_user(self):
        """Register a new user account."""
        username = self.reg_username.get().strip()
        password = self.reg_password.get().strip()
        confirm_password = self.reg_confirm_password.get().strip()
        
        if not username or not password:
            messagebox.showwarning("⚠️ Warning", "Username and password are required!")
            return
        
        if password != confirm_password:
            messagebox.showerror("❌ Error", "Passwords don't match!")
            return
        
        try:
            recovery_words = PasswordGenerator.generate_recovery_words()
            user_id = self.db.create_user(username, password, recovery_words)
            
            if user_id:
                recovery_message = "✅ Account created successfully!\n\n"
                recovery_message += "⚠️ SAVE THESE 8 WORDS IN ORDER:\n\n"
                for i, word in enumerate(recovery_words, 1):
                    recovery_message += f"  {i}. {word}\n"
                recovery_message += "\n📋 Copy and keep these words safe!\n"
                recovery_message += "You'll need them to recover your password.\n\n"
                recovery_message += "✅ With DEK architecture, your passwords\n"
                recovery_message += "   will survive password recovery!"
                
                messagebox.showinfo("🔑 Save Recovery Key", recovery_message)
                self.show_login_screen()
            else:
                messagebox.showerror("❌ Error", "Username already exists!")
        except Exception as e:
            messagebox.showerror("❌ Error", f"Registration failed: {str(e)}")
    
    def login(self):
        """Handle user login."""
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()
        
        if not username or not password:
            messagebox.showwarning("⚠️ Warning", "Enter username and password!")
            return
        
        try:
            user_id, data_key = self.db.verify_login(username, password)
            
            if user_id and data_key:
                self.current_user_id = user_id
                self.current_username = username
                self.data_key = data_key
                logger.info(f"User {username} logged in successfully")
                self.show_main_dashboard()
            else:
                messagebox.showerror("❌ Error", "Invalid username or password!")
        except Exception as e:
            logger.error(f"Login error: {e}")
            messagebox.showerror("❌ Error", f"Login failed: {str(e)}")
    
    def recover_password(self):
        """Handle password recovery without data loss."""
        username = self.recovery_username.get().strip()
        new_password = self.recovery_new_password.get().strip()
        
        recovery_words = [combo.get().strip().lower() for combo in self.recovery_combos]
        
        if not username or not new_password:
            messagebox.showwarning("⚠️ Warning", "Username and new password required!")
            return
        
        if any('select' in word.lower() or not word for word in recovery_words):
            messagebox.showwarning("⚠️ Warning", "Please select all 8 recovery words!")
            return
        
        if len(set(recovery_words)) != 8:
            messagebox.showwarning("⚠️ Warning", "All words must be unique!")
            return
        
        try:
            user_id, data_key = self.db.verify_recovery_key(username, recovery_words)
            
            if user_id and data_key:
                self.db.recovery_update_password(user_id, new_password, data_key)
                
                messagebox.showinfo("✅ Success", 
                                  "Password recovered successfully!\n\n"
                                  "🎉 ALL your stored passwords are preserved!\n"
                                  "🔐 The Data Encryption Key was recovered.\n\n"
                                  "Please login with your new password.")
                self.show_login_screen()
            else:
                messagebox.showerror("❌ Error", "Invalid recovery key or username!")
        except Exception as e:
            logger.error(f"Recovery error: {e}")
            messagebox.showerror("❌ Error", f"Recovery failed: {str(e)}")
    
    def load_passwords(self):
        """Load and display all passwords."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        if not self.data_key:
            logger.error("Data key not available")
            return
        
        try:
            passwords = self.db.get_passwords(self.current_user_id, self.data_key)
            
            for entry_id, title, username, password, description in passwords:
                self.tree.insert('', 'end', 
                               values=(title, username, password, description),
                               tags=(entry_id,))
        except Exception as e:
            logger.error(f"Error loading passwords: {e}")
    
    def export_database(self):
        """Export database to file."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".db",
            filetypes=[("Database files", "*.db")]
        )
        if file_path:
            try:
                self.db.export_database(file_path)
                messagebox.showinfo("✅ Success", f"Database exported to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("❌ Error", f"Export failed: {str(e)}")
    
    def import_database(self):
        """Import database from file."""
        file_path = filedialog.askopenfilename(
            filetypes=[("Database files", "*.db")]
        )
        if file_path:
            if messagebox.askyesno("⚠️ Confirm", "This will replace your current database. Continue?"):
                try:
                    self.db.import_database(file_path)
                    messagebox.showinfo("✅ Success", "Database imported successfully!")
                    self.show_login_screen()
                except Exception as e:
                    messagebox.showerror("❌ Error", f"Import failed: {str(e)}")
    
    def logout(self):
        """Logout current user."""
        self.current_user_id = None
        self.current_username = None
        self.data_key = None
        self.show_login_screen()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()