# CryptoTool Extension

## Overview

CryptoTool Extension is a comprehensive Chrome browser extension that provides a complete cryptographic toolkit. The extension offers various cryptographic operations including symmetric and asymmetric encryption, hash functions, classical ciphers, and encoding utilities. Built as a client-side application, it operates entirely within the browser environment without requiring external servers or network connectivity for core cryptographic operations.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
The extension follows a single-page application (SPA) pattern with a tabbed interface design. The architecture is built around:

- **Popup-based UI**: Uses Chrome extension popup window as the primary interface
- **Tab-based Navigation**: Organizes different cryptographic functions into logical categories (Symmetric, Asymmetric, Hash, Classical, Encoding, JSON)
- **Vanilla JavaScript**: No frontend frameworks used, keeping the bundle size minimal and reducing complexity
- **CSS3 Styling**: Modern glassmorphism design with gradient backgrounds and backdrop filters

### Component Structure
The extension is organized into distinct functional modules:

- **Tab Management System**: Handles navigation between different cryptographic categories
- **Symmetric Encryption Module**: Implements AES and RC4 algorithms with secure key derivation
- **Asymmetric Encryption Module**: Placeholder for RSA and other public-key cryptography
- **Hash Functions Module**: For implementing various hashing algorithms
- **Classical Ciphers Module**: Traditional encryption methods for educational purposes
- **Encoding Utilities Module**: Base64, URL encoding, and other encoding schemes
- **JSON Utilities Module**: JSON manipulation and formatting tools

### Security Architecture
The extension prioritizes client-side security:

- **Content Security Policy**: Strict CSP prevents execution of external scripts
- **Local Processing**: All cryptographic operations performed locally in the browser
- **No Network Dependencies**: Core functionality works offline
- **Secure Key Handling**: Uses PBKDF2 for key derivation in AES implementation

### Data Storage
Utilizes Chrome's storage API for:

- **User Preferences**: Storing algorithm preferences and UI settings
- **No Sensitive Data**: Keys and plaintext are never persisted
- **Session Management**: Temporary storage for user convenience features

### Build System
Simple build pipeline focused on:

- **File Copying**: Moves source files to distribution directory
- **Asset Management**: Handles icons and static resources
- **Packaging**: Creates ZIP archives for Chrome Web Store distribution
- **Development Workflow**: Watch mode for rapid development iteration

## External Dependencies

### Chrome Extension APIs
- **chrome.storage**: For storing user preferences and non-sensitive configuration data
- **Manifest V3**: Uses the latest Chrome extension manifest format for enhanced security

### Cryptographic Libraries
The extension implements cryptographic algorithms natively in JavaScript to maintain security and reduce external dependencies. Key implementations include:

- **AES Encryption**: Custom implementation with PBKDF2 key derivation
- **RC4 Cipher**: Basic implementation for educational purposes
- **Hash Functions**: Native JavaScript implementations of common hash algorithms

### Development Tools
- **NPM**: Package management and script execution
- **Standard Browser APIs**: Web Crypto API for secure random number generation and key derivation
- **Chrome DevTools**: Primary debugging and development environment

### Icon Assets
- **Custom Icons**: Self-contained icon set in multiple resolutions (16x16, 32x32, 48x48, 128x128)
- **No External CDNs**: All assets bundled with the extension for offline functionality

The architecture emphasizes security, simplicity, and offline functionality while providing a comprehensive cryptographic toolkit accessible through a user-friendly browser extension interface.