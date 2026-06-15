# 🔐 Secure Password Manager

A completely offline, desktop-based password management application built with Python that provides secure storage and management of your passwords using advanced encryption techniques.

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

## 📋 Table of Contents

- [Features](#features)
- [Security Architecture](#security-architecture)
- [Installation](#installation)
- [Quick Start Guide](#quick-start-guide)
- [User Guide](#user-guide)
- [Technical Details](#technical-details)
- [Database Portability](#database-portability)
- [Recovery System](#recovery-system)
- [File Structure](#file-structure)
- [Dependencies](#dependencies)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## ✨ Features

### Core Features
- **🔒 Complete Offline Operation** - No internet connection required, all data stored locally
- **🛡️ Military-Grade Encryption** - AES-128 encryption via Fernet with PBKDF2 key derivation
- **🔑 Secure Password Generator** - Creates strong 16-character random passwords
- **📋 Clipboard Integration** - Easy copy and paste functionality throughout the application
- **💾 Database Portability** - Export and import encrypted databases across systems
- **🔄 Password Change with Re-encryption** - Change master password without losing data
- **🔐 Recovery Key System** - 8-word recovery phrase for account recovery
- **✏️ Full CRUD Operations** - Create, Read, Update, and Delete password entries
- **👁️ Password Visibility Toggle** - Show/hide passwords as needed
- **📊 Intuitive Table View** - Clean, sortable display of all stored passwords

### Security Features
- SHA-256 hashing for user authentication
- Unique salt per user for both authentication and encryption
- PBKDF2HMAC with 100,000 iterations for key derivation
- Fernet (AES-128-CBC with HMAC) symmetric encryption
- Encrypted storage of all sensitive data
- Secure password generation using `secrets` module
- Automatic data cleanup on recovery

## 🔒 Security Architecture

### Authentication Layer
The application uses a two-tier security approach:

1. **User Authentication**: Passwords are hashed using SHA-256 with a unique 16-byte random salt for each user. The salt is stored alongside the hash in the database.

2. **Data Encryption**: A separate encryption key is derived from the user's master password using PBKDF2HMAC with SHA-256 and 100,000 iterations. This key is used to encrypt all stored password data using the Fernet protocol.

### Encryption Flow