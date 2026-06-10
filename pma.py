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
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ====================== ENCRYPTION MANAGER ======================
class EncryptionManager:
    @staticmethod
    def generate_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    @staticmethod
    def encrypt_data(data, key):
        if isinstance(data, str):
            data = data.encode('utf-8')
        f = Fernet(key)
        encrypted = f.encrypt(data)
        return encrypted
    
    @staticmethod
    def decrypt_data(encrypted_data, key):
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_data)
        return decrypted.decode('utf-8')


# ====================== DATABASE MANAGER ======================
class DatabaseManager:
    def __init__(self, db_path="password_manager.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username_hash TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                recovery_key_hash TEXT,
                salt TEXT NOT NULL,
                encryption_salt BLOB NOT NULL
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
        
        conn.commit()
        conn.close()
    
    def hash_data(self, data, salt=None):
        if salt is None:
            salt = secrets.token_hex(16)
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            data = str(data).encode('utf-8')
        
        hash_obj = hashlib.sha256(data + salt.encode('utf-8'))
        return hash_obj.hexdigest(), salt
    
    def create_user(self, username, password, recovery_words):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            auth_salt = secrets.token_hex(16)
            encryption_salt = secrets.token_bytes(16)
            
            username_hash, _ = self.hash_data(username, auth_salt)
            password_hash, _ = self.hash_data(password, auth_salt)
            
            recovery_key = " ".join(recovery_words)
            recovery_hash, _ = self.hash_data(recovery_key, auth_salt)
            
            cursor.execute('''
                INSERT INTO users (username_hash, password_hash, recovery_key_hash, salt, encryption_salt)
                VALUES (?, ?, ?, ?, ?)
            ''', (username_hash, password_hash, recovery_hash, auth_salt, encryption_salt))
            
            user_id = cursor.lastrowid
            conn.commit()
            return user_id
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()
    
    def verify_login(self, username, password):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, password_hash, salt, encryption_salt FROM users')
        users = cursor.fetchall()
        
        for user_id, stored_password_hash, auth_salt, encryption_salt in users:
            input_password_hash, _ = self.hash_data(password, auth_salt)
            if input_password_hash == stored_password_hash:
                cursor.execute('SELECT username_hash FROM users WHERE id = ?', (user_id,))
                stored_username_hash = cursor.fetchone()[0]
                
                input_username_hash, _ = self.hash_data(username, auth_salt)
                if input_username_hash == stored_username_hash:
                    encryption_key = EncryptionManager.generate_key(password, encryption_salt)
                    conn.close()
                    return user_id, encryption_key
        conn.close()
        return None, None
    
    def verify_recovery_key(self, username, recovery_words):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        recovery_key = " ".join(recovery_words)
        
        cursor.execute('SELECT id, recovery_key_hash, salt, encryption_salt FROM users')
        users = cursor.fetchall()
        
        for user_id, stored_recovery_hash, auth_salt, encryption_salt in users:
            input_recovery_hash, _ = self.hash_data(recovery_key, auth_salt)
            if input_recovery_hash == stored_recovery_hash:
                cursor.execute('SELECT username_hash FROM users WHERE id = ?', (user_id,))
                stored_username_hash = cursor.fetchone()[0]
                
                input_username_hash, _ = self.hash_data(username, auth_salt)
                if input_username_hash == stored_username_hash:
                    conn.close()
                    return user_id, encryption_salt
        conn.close()
        return None, None
    
    def update_password_and_reencrypt(self, user_id, old_password, new_password):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT salt, encryption_salt, password_hash FROM users WHERE id = ?', (user_id,))
            result = cursor.fetchone()
            if not result:
                conn.close()
                return False, "User not found"
            
            auth_salt, old_encryption_salt, stored_password_hash = result
            
            old_password_hash, _ = self.hash_data(old_password, auth_salt)
            if old_password_hash != stored_password_hash:
                conn.close()
                return False, "Current password is incorrect"
            
            old_encryption_key = EncryptionManager.generate_key(old_password, old_encryption_salt)
            
            cursor.execute('SELECT id, title_encrypted FROM passwords WHERE user_id = ? LIMIT 1', (user_id,))
            test_result = cursor.fetchone()
            
            if test_result:
                try:
                    EncryptionManager.decrypt_data(test_result[1], old_encryption_key)
                except Exception as e:
                    conn.close()
                    return False, "Cannot decrypt existing data with current password"
            
            new_encryption_salt = secrets.token_bytes(16)
            new_encryption_key = EncryptionManager.generate_key(new_password, new_encryption_salt)
            
            cursor.execute('SELECT id, title_encrypted, username_encrypted, password_encrypted, description_encrypted FROM passwords WHERE user_id = ?', (user_id,))
            all_passwords = cursor.fetchall()
            
            reencrypted_count = 0
            for pwd_id, title_enc, username_enc, password_enc, desc_enc in all_passwords:
                try:
                    title = EncryptionManager.decrypt_data(title_enc, old_encryption_key)
                    username = EncryptionManager.decrypt_data(username_enc, old_encryption_key)
                    password = EncryptionManager.decrypt_data(password_enc, old_encryption_key)
                    description = EncryptionManager.decrypt_data(desc_enc, old_encryption_key) if desc_enc else ""
                    
                    new_title_enc = EncryptionManager.encrypt_data(title, new_encryption_key)
                    new_username_enc = EncryptionManager.encrypt_data(username, new_encryption_key)
                    new_password_enc = EncryptionManager.encrypt_data(password, new_encryption_key)
                    new_desc_enc = EncryptionManager.encrypt_data(description, new_encryption_key) if description else None
                    
                    cursor.execute('''
                        UPDATE passwords 
                        SET title_encrypted = ?, username_encrypted = ?, password_encrypted = ?, description_encrypted = ?
                        WHERE id = ?
                    ''', (new_title_enc, new_username_enc, new_password_enc, new_desc_enc, pwd_id))
                    
                    reencrypted_count += 1
                    
                except Exception as e:
                    cursor.execute('DELETE FROM passwords WHERE id = ?', (pwd_id,))
                    print(f"Deleted corrupted entry {pwd_id}")
            
            new_password_hash, _ = self.hash_data(new_password, auth_salt)
            cursor.execute('''
                UPDATE users SET password_hash = ?, encryption_salt = ?
                WHERE id = ?
            ''', (new_password_hash, new_encryption_salt, user_id))
            
            conn.commit()
            conn.close()
            
            return True, (new_encryption_key, reencrypted_count)
            
        except Exception as e:
            conn.rollback()
            conn.close()
            return False, f"Error: {str(e)}"
    
    def update_password_recovery(self, user_id, new_password):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT salt FROM users WHERE id = ?', (user_id,))
            auth_salt = cursor.fetchone()[0]
            
            new_password_hash, _ = self.hash_data(new_password, auth_salt)
            new_encryption_salt = secrets.token_bytes(16)
            
            cursor.execute('DELETE FROM passwords WHERE user_id = ?', (user_id,))
            
            cursor.execute('''
                UPDATE users SET password_hash = ?, encryption_salt = ?
                WHERE id = ?
            ''', (new_password_hash, new_encryption_salt, user_id))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            conn.rollback()
            conn.close()
            return False
    
    def add_password(self, user_id, encryption_key, title, username, password, description=""):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            title_encrypted = EncryptionManager.encrypt_data(title, encryption_key)
            username_encrypted = EncryptionManager.encrypt_data(username, encryption_key)
            password_encrypted = EncryptionManager.encrypt_data(password, encryption_key)
            description_encrypted = EncryptionManager.encrypt_data(description, encryption_key) if description else None
            
            cursor.execute('''
                INSERT INTO passwords (user_id, title_encrypted, username_encrypted, password_encrypted, description_encrypted)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, title_encrypted, username_encrypted, password_encrypted, description_encrypted))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding password: {e}")
            return False
        finally:
            conn.close()
    
    def get_passwords(self, user_id, encryption_key):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, title_encrypted, username_encrypted, password_encrypted, description_encrypted
            FROM passwords WHERE user_id = ?
        ''', (user_id,))
        
        encrypted_passwords = cursor.fetchall()
        conn.close()
        
        decrypted_passwords = []
        for entry_id, title_enc, username_enc, password_enc, desc_enc in encrypted_passwords:
            try:
                title = EncryptionManager.decrypt_data(title_enc, encryption_key)
                username = EncryptionManager.decrypt_data(username_enc, encryption_key)
                password = EncryptionManager.decrypt_data(password_enc, encryption_key)
                description = EncryptionManager.decrypt_data(desc_enc, encryption_key) if desc_enc else ""
                
                decrypted_passwords.append((entry_id, title, username, password, description))
            except Exception as e:
                print(f"Error decrypting password {entry_id}: {e}")
                continue
        
        return decrypted_passwords
    
    def update_password_entry(self, entry_id, encryption_key, title, username, password, description):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            title_encrypted = EncryptionManager.encrypt_data(title, encryption_key)
            username_encrypted = EncryptionManager.encrypt_data(username, encryption_key)
            password_encrypted = EncryptionManager.encrypt_data(password, encryption_key)
            description_encrypted = EncryptionManager.encrypt_data(description, encryption_key) if description else None
            
            cursor.execute('''
                UPDATE passwords 
                SET title_encrypted = ?, username_encrypted = ?, password_encrypted = ?, 
                    description_encrypted = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (title_encrypted, username_encrypted, password_encrypted, 
                  description_encrypted, entry_id))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Error updating password: {e}")
            return False
        finally:
            conn.close()
    
    def delete_password(self, entry_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))
        conn.commit()
        conn.close()
    
    def export_database(self, export_path):
        shutil.copy2(self.db_path, export_path)
    
    def import_database(self, import_path):
        shutil.copy2(import_path, self.db_path)
        self.init_database()


# ====================== PASSWORD GENERATOR ======================
class PasswordGenerator:
    @staticmethod
    def generate_secure_password(length=16):
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
    def generate_recovery_words():
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
    def get_all_words():
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
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("500x500")
        self.root.resizable(False, False)
        self.root.configure(bg='#f0f0f0')
        
        self.db = DatabaseManager()
        self.current_user_id = None
        self.current_username = None
        self.encryption_key = None
        
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
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def create_styled_button(self, parent, text, command, color, width=20, height=1):
        return tk.Button(parent, text=text, command=command,
                        bg=color, fg='white', font=('Arial', 10, 'bold'),
                        width=width, height=height, bd=0, padx=10, pady=8,
                        cursor='hand2',
                        activebackground=color, activeforeground='white')
    
    def show_login_screen(self):
        self.clear_screen()
        self.root.geometry("500x500")
        self.root.resizable(False, False)
        
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(expand=True, fill='both', padx=30, pady=30)
        
        tk.Label(main_frame, text="🔐 Password Manager", 
                font=('Arial', 18, 'bold'),
                bg=self.colors['bg'],
                fg=self.colors['primary']).pack(pady=(20, 30))
        
        form_frame = tk.Frame(main_frame, bg='white', relief='flat', bd=0)
        form_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(form_frame, text="👤 Username:", bg='white',
                font=('Arial', 10)).pack(pady=(15, 5))
        self.login_username = tk.Entry(form_frame, font=('Arial', 11), width=30, bd=1, relief='solid')
        self.login_username.pack(pady=(0, 10), ipady=3)
        
        tk.Label(form_frame, text="🔑 Password:", bg='white',
                font=('Arial', 10)).pack(pady=(5, 5))
        self.login_password = tk.Entry(form_frame, show="*", font=('Arial', 11), width=30, bd=1, relief='solid')
        self.login_password.pack(pady=(0, 20), ipady=3)
        
        self.create_styled_button(form_frame, "Login", self.login, self.colors['secondary']).pack(pady=5)
        self.create_styled_button(form_frame, "Create Account", self.show_register_screen, self.colors['success']).pack(pady=5)
        
        tk.Button(form_frame, text="Forgot Password?",
                 command=self.show_recovery_screen,
                 bg='white', fg=self.colors['secondary'],
                 font=('Arial', 9, 'underline'), bd=0, cursor='hand2').pack(pady=(10, 5))
        
        tk.Button(form_frame, text="Import Database",
                 command=self.import_database,
                 bg='white', fg=self.colors['warning'],
                 font=('Arial', 9, 'underline'), bd=0, cursor='hand2').pack(pady=(0, 10))
    
    def show_register_screen(self):
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
        
        tk.Label(form_frame, text="🔑 Password:", bg='white',
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
        self.clear_screen()
        self.root.geometry("500x600")
        
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        tk.Label(main_frame, text="Password Recovery", font=('Arial', 16, 'bold'),
                bg=self.colors['bg'], fg=self.colors['primary']).pack(pady=(10, 15))
        
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
        
        tk.Label(form_frame, text="🔑 New Password:", bg='white',
                font=('Arial', 10)).pack(pady=(10, 5))
        self.recovery_new_password = tk.Entry(form_frame, show="*", font=('Arial', 11), 
                                              width=35, bd=1, relief='solid')
        self.recovery_new_password.pack(pady=(0, 10), ipady=2)
        
        tk.Label(form_frame, 
                text="⚠️ All stored passwords will be deleted after recovery!",
                bg='white', fg=self.colors['danger'],
                font=('Arial', 8, 'bold')).pack(pady=5)
        
        self.create_styled_button(form_frame, "✅ Confirm & Recover Password", 
                                 self.recover_password, 
                                 self.colors['warning'], width=25, height=2).pack(pady=15)
        
        self.create_styled_button(form_frame, "← Back to Login", 
                                 self.show_login_screen, 
                                 self.colors['danger'], width=25).pack(pady=5)
    
    def show_main_dashboard(self):
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
        file_menu.add_command(label="Change Password", command=self.show_change_password)
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
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password" if not edit_mode else "Edit Password")
        dialog.geometry("500x650")
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
        tk.Label(main_frame, text="Title:", bg='white', font=('Arial', 10, 'bold')).pack(pady=(15, 5))
        title_entry = tk.Entry(main_frame, font=('Arial', 11), width=40, bd=1, relief='solid')
        title_entry.insert(0, current_title)
        title_entry.pack(pady=(0, 10), ipady=2)
        
        # Username
        tk.Label(main_frame, text="Username:", bg='white', font=('Arial', 10, 'bold')).pack(pady=(5, 5))
        username_entry = tk.Entry(main_frame, font=('Arial', 11), width=40, bd=1, relief='solid')
        username_entry.insert(0, current_username)
        username_entry.pack(pady=(0, 10), ipady=2)
        
        # Password
        tk.Label(main_frame, text="Password:", bg='white', font=('Arial', 10, 'bold')).pack(pady=(5, 5))
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
        
        self.create_styled_button(pwd_btn_frame, "Show/Hide", toggle_password_visibility,
                                 self.colors['warning'], width=10).pack(side='left', padx=3)
        
        self.create_styled_button(pwd_btn_frame, "Generate", 
                                 lambda: [password_entry.delete(0, tk.END), 
                                        password_entry.insert(0, PasswordGenerator.generate_secure_password()),
                                        password_entry.config(show='')],
                                 self.colors['secondary'], width=10).pack(side='left', padx=3)
        
        self.create_styled_button(pwd_btn_frame, "Copy", 
                                 lambda: [self.root.clipboard_clear(), 
                                         self.root.clipboard_append(password_entry.get()),
                                         messagebox.showinfo("Copied", "Password copied!")] if password_entry.get() 
                                         else messagebox.showwarning("Warning", "No password!"),
                                 self.colors['success'], width=8).pack(side='left', padx=3)
        
        # Confirm Password
        tk.Label(main_frame, text="Confirm Password:", bg='white', font=('Arial', 10, 'bold')).pack(pady=(10, 5))
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
        
        self.create_styled_button(confirm_btn_frame, "Show/Hide", toggle_confirm_visibility,
                                 self.colors['warning'], width=10).pack(side='left', padx=3)
        
        self.create_styled_button(confirm_btn_frame, "Paste", 
                                 lambda: [confirm_password_entry.delete(0, tk.END),
                                         confirm_password_entry.insert(0, self.root.clipboard_get())] 
                                         if self.root.clipboard_get() else None,
                                 self.colors['secondary'], width=10).pack(side='left', padx=3)
        
        # Description
        tk.Label(main_frame, text="Description:", bg='white', font=('Arial', 10, 'bold')).pack(pady=(5, 5))
        description_text = tk.Text(main_frame, font=('Arial', 11), width=40, height=3, bd=1, relief='solid')
        description_text.insert('1.0', current_description)
        description_text.pack(pady=(0, 10))
        
        # BIG CONFIRM BUTTON
        def save_password():
            title = title_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            confirm_password = confirm_password_entry.get().strip()
            description = description_text.get('1.0', 'end-1c').strip()
            
            if not title or not username or not password:
                messagebox.showwarning("Warning", "Title, username and password are required!")
                return
            
            if password != confirm_password:
                messagebox.showerror("Error", "❌ Passwords do not match!\nPlease check Confirm Password field.")
                return
            
            if edit_mode and entry_id:
                success = self.db.update_password_entry(
                    int(entry_id), self.encryption_key, title, username, password, description
                )
                if success:
                    messagebox.showinfo("Success", "✅ Password updated successfully!")
                    self.load_passwords()
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Failed to update password!")
            else:
                success = self.db.add_password(
                    self.current_user_id, self.encryption_key, title, username, password, description
                )
                if success:
                    messagebox.showinfo("Success", "✅ Password saved to database!")
                    self.load_passwords()
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Failed to save password!")
        
        # BIG SAVE BUTTON
        self.create_styled_button(main_frame, "💾 SAVE TO DATABASE", save_password,
                                 self.colors['success'], width=25, height=2).pack(pady=15)
        
        self.create_styled_button(main_frame, "Cancel", dialog.destroy,
                                 self.colors['danger'], width=25).pack(pady=5)
    
    def show_edit_password(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an entry to edit!")
            return
        self.show_add_password(edit_mode=True)
    
    def show_change_password(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Password (Keep Data)")
        dialog.geometry("420x400")
        dialog.configure(bg=self.colors['bg'])
        dialog.resizable(False, False)
        
        main_frame = tk.Frame(dialog, bg='white', relief='solid', bd=1)
        main_frame.pack(expand=True, fill='both', padx=15, pady=15)
        
        tk.Label(main_frame, text="🔑 Change Password", font=('Arial', 14, 'bold'),
                bg='white', fg=self.colors['primary']).pack(pady=15)
        
        tk.Label(main_frame, text="✅ Your data will be re-encrypted safely",
                bg='white', fg=self.colors['success'],
                font=('Arial', 9)).pack()
        
        tk.Label(main_frame, text="Current Password:", bg='white', 
                font=('Arial', 10)).pack(pady=(15, 5))
        old_password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11), 
                                      width=30, bd=1, relief='solid')
        old_password_entry.pack(pady=(0, 10), ipady=2)
        
        tk.Label(main_frame, text="New Password:", bg='white', 
                font=('Arial', 10)).pack(pady=(5, 5))
        new_password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11), 
                                      width=30, bd=1, relief='solid')
        new_password_entry.pack(pady=(0, 10), ipady=2)
        
        tk.Label(main_frame, text="Confirm New Password:", bg='white', 
                font=('Arial', 10)).pack(pady=(5, 5))
        confirm_new_password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11), 
                                              width=30, bd=1, relief='solid')
        confirm_new_password_entry.pack(pady=(0, 10), ipady=2)
        
        def change_password():
            old_password = old_password_entry.get().strip()
            new_password = new_password_entry.get().strip()
            confirm_new = confirm_new_password_entry.get().strip()
            
            if not old_password or not new_password or not confirm_new:
                messagebox.showwarning("Warning", "All fields are required!")
                return
            
            if new_password != confirm_new:
                messagebox.showerror("Error", "New passwords don't match!")
                return
            
            if old_password == new_password:
                messagebox.showwarning("Warning", "New password is same as current!")
                return
            
            success, result = self.db.update_password_and_reencrypt(
                self.current_user_id, old_password, new_password
            )
            
            if success:
                new_encryption_key, count = result
                self.encryption_key = new_encryption_key
                messagebox.showinfo("Success", 
                                  f"✅ Password changed successfully!\n"
                                  f"📊 {count} passwords re-encrypted.\n"
                                  f"🔐 Your data is safe.")
                dialog.destroy()
                self.load_passwords()
            else:
                messagebox.showerror("Error", f"❌ {result}")
        
        self.create_styled_button(main_frame, "✅ Confirm Change Password", change_password,
                                 self.colors['success'], width=25, height=2).pack(pady=20)
        
        self.create_styled_button(main_frame, "Cancel", dialog.destroy,
                                 self.colors['danger'], width=25).pack(pady=5)
    
    def delete_password(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an entry to delete!")
            return
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            item = self.tree.item(selection[0])
            entry_id = item['tags'][0] if item['tags'] else None
            
            if entry_id:
                self.db.delete_password(int(entry_id))
                self.load_passwords()
                messagebox.showinfo("Success", "✅ Entry deleted!")
    
    def copy_username(self):
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            username = item['values'][1]
            self.root.clipboard_clear()
            self.root.clipboard_append(username)
            messagebox.showinfo("Copied", "Username copied!")
    
    def copy_password(self):
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            password = item['values'][2]
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied!")
    
    def generate_and_show_password(self):
        password = PasswordGenerator.generate_secure_password()
        self.reg_password.delete(0, tk.END)
        self.reg_password.insert(0, password)
        self.reg_password.config(show='')
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("Password Generated", 
                          "✅ Strong password generated!\n"
                          "• Visible in field\n"
                          "• Copied to clipboard")
    
    def toggle_reg_password(self):
        if self.reg_password.cget('show') == '*':
            self.reg_password.config(show='')
        else:
            self.reg_password.config(show='*')
    
    def copy_reg_password(self):
        password = self.reg_password.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied!")
    
    def paste_to_confirm(self):
        try:
            clipboard_text = self.root.clipboard_get()
            self.reg_confirm_password.delete(0, tk.END)
            self.reg_confirm_password.insert(0, clipboard_text)
            messagebox.showinfo("Pasted", "Pasted from clipboard!")
        except:
            messagebox.showwarning("Warning", "Clipboard is empty!")
    
    def register_user(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get().strip()
        confirm_password = self.reg_confirm_password.get().strip()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Username and password are required!")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords don't match!")
            return
        
        recovery_words = PasswordGenerator.generate_recovery_words()
        user_id = self.db.create_user(username, password, recovery_words)
        
        if user_id:
            recovery_message = "✅ Account created!\n\n"
            recovery_message += "⚠️ SAVE THESE 8 WORDS IN ORDER:\n\n"
            for i, word in enumerate(recovery_words, 1):
                recovery_message += f"  {i}. {word}\n"
            recovery_message += "\n📋 Copy and save safely!"
            
            messagebox.showinfo("Save Recovery Key", recovery_message)
            self.show_login_screen()
        else:
            messagebox.showerror("Error", "Username already exists!")
    
    def login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Enter username and password!")
            return
        
        user_id, encryption_key = self.db.verify_login(username, password)
        
        if user_id and encryption_key:
            self.current_user_id = user_id
            self.current_username = username
            self.encryption_key = encryption_key
            self.show_main_dashboard()
        else:
            messagebox.showerror("Error", "Invalid username or password!")
    
    def recover_password(self):
        username = self.recovery_username.get().strip()
        new_password = self.recovery_new_password.get().strip()
        
        recovery_words = [combo.get().strip().lower() for combo in self.recovery_combos]
        
        if not username or not new_password:
            messagebox.showwarning("Warning", "Username and new password required!")
            return
        
        if any('select' in word.lower() or not word for word in recovery_words):
            messagebox.showwarning("Warning", "Please select all 8 recovery words!")
            return
        
        if len(set(recovery_words)) != 8:
            messagebox.showwarning("Warning", "All words must be unique!")
            return
        
        user_id, encryption_salt = self.db.verify_recovery_key(username, recovery_words)
        
        if user_id:
            self.db.update_password_recovery(user_id, new_password)
            messagebox.showinfo("Success", 
                              "✅ Password reset!\n\n"
                              "⚠️ All stored passwords have been deleted.\n"
                              "Login and add your passwords again.")
            self.show_login_screen()
        else:
            messagebox.showerror("Error", "Invalid recovery key or username!")
    
    def load_passwords(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        passwords = self.db.get_passwords(self.current_user_id, self.encryption_key)
        
        for entry_id, title, username, password, description in passwords:
            self.tree.insert('', 'end', 
                           values=(title, username, password, description),
                           tags=(entry_id,))
    
    def export_database(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".db",
            filetypes=[("Database files", "*.db")]
        )
        if file_path:
            self.db.export_database(file_path)
            messagebox.showinfo("Success", f"✅ Database exported!")
    
    def import_database(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Database files", "*.db")]
        )
        if file_path:
            if messagebox.askyesno("Confirm", "Replace current database?"):
                self.db.import_database(file_path)
                messagebox.showinfo("Success", "✅ Database imported!")
                self.show_login_screen()
    
    def logout(self):
        self.current_user_id = None
        self.current_username = None
        self.encryption_key = None
        self.show_login_screen()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
