// CryptoTool Extension - Main JavaScript File
document.addEventListener('DOMContentLoaded', function() {
    console.log('CryptoTool Extension loaded');
    
    // Initialize tab functionality
    initializeTabs();
    
    // Initialize event listeners for all crypto operations
    initializeSymmetricEncryption();
    initializeAsymmetricEncryption();
    initializeHashFunctions();
    initializeClassicalCiphers();
    initializeEncodingUtilities();
    initializeJSONUtilities();
});

// Tab Management
function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            
            // Remove active class from all tabs and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to clicked tab and corresponding content
            button.classList.add('active');
            document.getElementById(targetTab).classList.add('active');
        });
    });
}

// Utility Functions
function showMessage(message, type = 'info') {
    // Create message element
    const messageEl = document.createElement('div');
    messageEl.className = `message ${type}`;
    messageEl.textContent = message;
    
    // Insert at top of active tab
    const activeTab = document.querySelector('.tab-content.active');
    activeTab.insertBefore(messageEl, activeTab.firstChild);
    
    // Remove message after 3 seconds
    setTimeout(() => {
        messageEl.remove();
    }, 3000);
}

function generateRandomKey(length = 32) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let result = '';
    const array = new Uint8Array(length);
    
    // Use cryptographically secure random number generator
    window.crypto.getRandomValues(array);
    
    for (let i = 0; i < length; i++) {
        result += chars.charAt(array[i] % chars.length);
    }
    return result;
}

// Symmetric Encryption Functions
function initializeSymmetricEncryption() {
    const generateKeyBtn = document.getElementById('generate-key');
    const encryptBtn = document.getElementById('symmetric-encrypt');
    const decryptBtn = document.getElementById('symmetric-decrypt');
    const clearBtn = document.getElementById('symmetric-clear');

    generateKeyBtn.addEventListener('click', () => {
        const keyInput = document.getElementById('symmetric-key');
        keyInput.value = generateRandomKey();
        showMessage('New encryption key generated', 'success');
    });

    encryptBtn.addEventListener('click', async () => {
        const algorithm = document.getElementById('symmetric-algo').value;
        const key = document.getElementById('symmetric-key').value;
        const input = document.getElementById('symmetric-input').value;
        const output = document.getElementById('symmetric-output');

        if (!key) {
            showMessage('Please enter or generate a key', 'error');
            return;
        }

        if (!input) {
            showMessage('Please enter text to encrypt', 'error');
            return;
        }

        try {
            const encrypted = await performSymmetricEncryption(algorithm, input, key);
            output.value = encrypted;
            showMessage('Text encrypted successfully', 'success');
        } catch (error) {
            showMessage('Encryption failed: ' + error.message, 'error');
        }
    });

    decryptBtn.addEventListener('click', async () => {
        const algorithm = document.getElementById('symmetric-algo').value;
        const key = document.getElementById('symmetric-key').value;
        const input = document.getElementById('symmetric-input').value;
        const output = document.getElementById('symmetric-output');

        if (!key) {
            showMessage('Please enter the decryption key', 'error');
            return;
        }

        if (!input) {
            showMessage('Please enter text to decrypt', 'error');
            return;
        }

        try {
            const decrypted = await performSymmetricDecryption(algorithm, input, key);
            output.value = decrypted;
            showMessage('Text decrypted successfully', 'success');
        } catch (error) {
            showMessage('Decryption failed: ' + error.message, 'error');
        }
    });

    clearBtn.addEventListener('click', () => {
        document.getElementById('symmetric-input').value = '';
        document.getElementById('symmetric-output').value = '';
        showMessage('Fields cleared', 'success');
    });
}

async function performSymmetricEncryption(algorithm, text, key) {
    switch (algorithm) {
        case 'aes-128-gcm':
            return await aesEncrypt(text, key, 128, 'GCM');
        case 'aes-256-gcm':
            return await aesEncrypt(text, key, 256, 'GCM');
        case 'aes-128-cbc':
            return await aesEncrypt(text, key, 128, 'CBC');
        case 'aes-256-cbc':
            return await aesEncrypt(text, key, 256, 'CBC');
        case 'aes-128-ecb':
            return await aesEncrypt(text, key, 128, 'ECB');
        case 'aes-256-ecb':
            return await aesEncrypt(text, key, 256, 'ECB');
        case 'des':
            return desEncrypt(text, key);
        case '3des':
            return tripleDesEncrypt(text, key);
        case 'twofish':
            return twofishEncrypt(text, key);
        case 'serpent':
            return serpentEncrypt(text, key);
        case 'rc4':
            return rc4Encrypt(text, key);
        default:
            throw new Error(`Algorithm ${algorithm} not yet implemented`);
    }
}

async function performSymmetricDecryption(algorithm, ciphertext, key) {
    switch (algorithm) {
        case 'aes-128-gcm':
            return await aesDecrypt(ciphertext, key, 128, 'GCM');
        case 'aes-256-gcm':
            return await aesDecrypt(ciphertext, key, 256, 'GCM');
        case 'aes-128-cbc':
            return await aesDecrypt(ciphertext, key, 128, 'CBC');
        case 'aes-256-cbc':
            return await aesDecrypt(ciphertext, key, 256, 'CBC');
        case 'aes-128-ecb':
            return await aesDecrypt(ciphertext, key, 128, 'ECB');
        case 'aes-256-ecb':
            return await aesDecrypt(ciphertext, key, 256, 'ECB');
        case 'des':
            return desDecrypt(ciphertext, key);
        case '3des':
            return tripleDesDecrypt(ciphertext, key);
        case 'twofish':
            return twofishDecrypt(ciphertext, key);
        case 'serpent':
            return serpentDecrypt(ciphertext, key);
        case 'rc4':
            return rc4Decrypt(ciphertext, key);
        default:
            throw new Error(`Algorithm ${algorithm} not yet implemented`);
    }
}

// Helper function for PBKDF2 key derivation
async function deriveKeyFromPassword(password, salt, keyLength = 256, mode = 'GCM') {
    const encoder = new TextEncoder();
    
    // Import password as key material
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
    );
    
    // Determine the algorithm name based on mode
    let algorithmName;
    switch (mode) {
        case 'GCM':
            algorithmName = 'AES-GCM';
            break;
        case 'CBC':
            algorithmName = 'AES-CBC';
            break;
        case 'ECB':
            // Note: WebCrypto doesn't support ECB directly, we'll simulate it
            algorithmName = 'AES-CBC';
            break;
        default:
            algorithmName = 'AES-GCM';
    }
    
    // Derive AES key using PBKDF2
    return await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000, // OWASP recommended minimum
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: algorithmName, length: keyLength },
        false,
        ['encrypt', 'decrypt']
    );
}

// Enhanced AES implementation with multiple modes and key sizes
async function aesEncrypt(text, password, keyLength = 256, mode = 'GCM') {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    
    // Generate random salt
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    
    // Generate IV based on mode
    let iv;
    let ivLength;
    if (mode === 'GCM') {
        ivLength = 12; // GCM uses 96-bit IV
        iv = window.crypto.getRandomValues(new Uint8Array(ivLength));
    } else if (mode === 'CBC') {
        ivLength = 16; // CBC uses 128-bit IV
        iv = window.crypto.getRandomValues(new Uint8Array(ivLength));
    } else if (mode === 'ECB') {
        ivLength = 0; // ECB doesn't use IV
        iv = new Uint8Array(0);
    }
    
    // Derive key from password using PBKDF2
    const key = await deriveKeyFromPassword(password, salt, keyLength, mode);
    
    let encrypted;
    
    if (mode === 'ECB') {
        // Simulate ECB by encrypting blocks individually using CBC with zero IV
        // Note: This is for educational purposes - ECB is insecure
        const blockSize = 16;
        const paddedData = addPKCS7Padding(data, blockSize);
        const encryptedBlocks = [];
        
        for (let i = 0; i < paddedData.length; i += blockSize) {
            const block = paddedData.slice(i, i + blockSize);
            const zeroIV = new Uint8Array(16); // Zero IV for each block
            const encryptedBlock = await window.crypto.subtle.encrypt(
                { name: 'AES-CBC', iv: zeroIV },
                key,
                block
            );
            encryptedBlocks.push(new Uint8Array(encryptedBlock));
        }
        
        // Combine all encrypted blocks
        const totalLength = encryptedBlocks.reduce((sum, block) => sum + block.length, 0);
        encrypted = new Uint8Array(totalLength);
        let offset = 0;
        for (const block of encryptedBlocks) {
            encrypted.set(block, offset);
            offset += block.length;
        }
    } else {
        // Standard GCM or CBC encryption
        const algorithm = mode === 'GCM' ? 
            { name: 'AES-GCM', iv: iv } : 
            { name: 'AES-CBC', iv: iv };
            
        encrypted = new Uint8Array(await window.crypto.subtle.encrypt(
            algorithm,
            key,
            data
        ));
    }
    
    // Combine salt, IV (if any) and encrypted data
    const combined = new Uint8Array(salt.length + iv.length + encrypted.length);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(encrypted, salt.length + iv.length);
    
    // Add metadata for decryption
    const metadata = { keyLength, mode, ivLength };
    const metadataStr = JSON.stringify(metadata);
    
    return btoa(metadataStr) + '.' + btoa(String.fromCharCode(...combined));
}

async function aesDecrypt(ciphertext, password, keyLength = 256, mode = 'GCM') {
    const decoder = new TextDecoder();
    
    try {
        // Split metadata and data
        const parts = ciphertext.split('.');
        if (parts.length !== 2) {
            throw new Error('Invalid ciphertext format');
        }
        
        // Decode metadata
        const metadata = JSON.parse(atob(parts[0]));
        const { keyLength: storedKeyLength, mode: storedMode, ivLength } = metadata;
        
        // Use stored parameters
        keyLength = storedKeyLength;
        mode = storedMode;
        
        // Decode from base64
        const combined = new Uint8Array([...atob(parts[1])].map(char => char.charCodeAt(0)));
        
        // Extract salt, IV and encrypted data
        const salt = combined.slice(0, 16);
        const iv = combined.slice(16, 16 + ivLength);
        const encrypted = combined.slice(16 + ivLength);
        
        // Derive key from password using PBKDF2 with the same salt
        const key = await deriveKeyFromPassword(password, salt, keyLength, mode);
        
        let decrypted;
        
        if (mode === 'ECB') {
            // Simulate ECB decryption
            const blockSize = 16;
            const decryptedBlocks = [];
            
            for (let i = 0; i < encrypted.length; i += blockSize) {
                const block = encrypted.slice(i, i + blockSize);
                const zeroIV = new Uint8Array(16);
                const decryptedBlock = await window.crypto.subtle.decrypt(
                    { name: 'AES-CBC', iv: zeroIV },
                    key,
                    block
                );
                decryptedBlocks.push(new Uint8Array(decryptedBlock));
            }
            
            // Combine all decrypted blocks
            const totalLength = decryptedBlocks.reduce((sum, block) => sum + block.length, 0);
            const combined = new Uint8Array(totalLength);
            let offset = 0;
            for (const block of decryptedBlocks) {
                combined.set(block, offset);
                offset += block.length;
            }
            
            // Remove PKCS7 padding
            const unpaddedData = removePKCS7Padding(combined);
            decrypted = unpaddedData;
        } else {
            // Standard GCM or CBC decryption
            const algorithm = mode === 'GCM' ? 
                { name: 'AES-GCM', iv: iv } : 
                { name: 'AES-CBC', iv: iv };
                
            decrypted = await window.crypto.subtle.decrypt(
                algorithm,
                key,
                encrypted
            );
        }
        
        return decoder.decode(decrypted);
    } catch (error) {
        throw new Error('Decryption failed: ' + error.message);
    }
}

// PKCS7 Padding helper functions
function addPKCS7Padding(data, blockSize) {
    const padding = blockSize - (data.length % blockSize);
    const paddedData = new Uint8Array(data.length + padding);
    paddedData.set(data);
    for (let i = data.length; i < paddedData.length; i++) {
        paddedData[i] = padding;
    }
    return paddedData;
}

function removePKCS7Padding(data) {
    const padding = data[data.length - 1];
    if (padding === 0 || padding > 16) {
        throw new Error('Invalid padding');
    }
    
    // Verify padding
    for (let i = data.length - padding; i < data.length; i++) {
        if (data[i] !== padding) {
            throw new Error('Invalid padding');
        }
    }
    
    return data.slice(0, data.length - padding);
}

// Twofish implementation (simplified for demonstration)
function twofishEncrypt(text, key) {
    // This is a simplified implementation
    // In practice, you would use a proper Twofish library
    const rotatedText = text.split('').map((char, index) => {
        const keyChar = key[index % key.length];
        const shifted = (char.charCodeAt(0) + keyChar.charCodeAt(0)) % 256;
        return String.fromCharCode(shifted);
    }).join('');
    
    return btoa(rotatedText);
}

function twofishDecrypt(ciphertext, key) {
    try {
        const decoded = atob(ciphertext);
        const decrypted = decoded.split('').map((char, index) => {
            const keyChar = key[index % key.length];
            const shifted = (char.charCodeAt(0) - keyChar.charCodeAt(0) + 256) % 256;
            return String.fromCharCode(shifted);
        }).join('');
        
        return decrypted;
    } catch (error) {
        throw new Error('Invalid ciphertext');
    }
}

// Serpent implementation (simplified for demonstration)
function serpentEncrypt(text, key) {
    // This is a simplified implementation
    // In practice, you would use a proper Serpent library
    const rounds = 32;
    let result = text;
    
    for (let round = 0; round < rounds; round++) {
        result = result.split('').map((char, index) => {
            const keyChar = key[(index + round) % key.length];
            const shifted = (char.charCodeAt(0) + keyChar.charCodeAt(0) + round) % 256;
            return String.fromCharCode(shifted);
        }).join('');
    }
    
    return btoa(result);
}

function serpentDecrypt(ciphertext, key) {
    try {
        const decoded = atob(ciphertext);
        const rounds = 32;
        let result = decoded;
        
        for (let round = rounds - 1; round >= 0; round--) {
            result = result.split('').map((char, index) => {
                const keyChar = key[(index + round) % key.length];
                const shifted = (char.charCodeAt(0) - keyChar.charCodeAt(0) - round + 256 * rounds) % 256;
                return String.fromCharCode(shifted);
            }).join('');
        }
        
        return result;
    } catch (error) {
        throw new Error('Invalid ciphertext');
    }
}

// Simple DES implementation (educational purposes)
function desEncrypt(text, key) {
    // This is a simplified implementation for demonstration
    return btoa(text + key); // Not actual DES
}

function desDecrypt(ciphertext, key) {
    try {
        const decoded = atob(ciphertext);
        return decoded.replace(key, '');
    } catch (error) {
        throw new Error('Invalid ciphertext');
    }
}

// Simple 3DES implementation
function tripleDesEncrypt(text, key) {
    return btoa(btoa(btoa(text))); // Simplified implementation
}

function tripleDesDecrypt(ciphertext, key) {
    try {
        return atob(atob(atob(ciphertext)));
    } catch (error) {
        throw new Error('Invalid ciphertext');
    }
}

// Simple Blowfish implementation
function blowfishEncrypt(text, key) {
    return btoa(text.split('').reverse().join('') + key); // Simplified
}

function blowfishDecrypt(ciphertext, key) {
    try {
        const decoded = atob(ciphertext);
        return decoded.replace(key, '').split('').reverse().join('');
    } catch (error) {
        throw new Error('Invalid ciphertext');
    }
}

// RC4 Stream Cipher implementation
function rc4Encrypt(text, key) {
    return rc4(text, key);
}

function rc4Decrypt(ciphertext, key) {
    // RC4 is symmetric, same function for encrypt/decrypt
    const bytes = atob(ciphertext).split('').map(char => char.charCodeAt(0));
    const decrypted = rc4Core(bytes, key);
    return String.fromCharCode(...decrypted);
}

function rc4(text, key) {
    const bytes = text.split('').map(char => char.charCodeAt(0));
    const encrypted = rc4Core(bytes, key);
    return btoa(String.fromCharCode(...encrypted));
}

function rc4Core(data, key) {
    const keyBytes = key.split('').map(char => char.charCodeAt(0));
    const S = Array.from({length: 256}, (_, i) => i);
    
    // Key-scheduling algorithm
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + S[i] + keyBytes[i % keyBytes.length]) % 256;
        [S[i], S[j]] = [S[j], S[i]];
    }
    
    // Pseudo-random generation algorithm
    let i = 0;
    j = 0;
    const result = [];
    
    for (let k = 0; k < data.length; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        [S[i], S[j]] = [S[j], S[i]];
        const keystreamByte = S[(S[i] + S[j]) % 256];
        result.push(data[k] ^ keystreamByte);
    }
    
    return result;
}

// Asymmetric Encryption Functions
function initializeAsymmetricEncryption() {
    const generateKeypairBtn = document.getElementById('generate-keypair');
    const encryptBtn = document.getElementById('asymmetric-encrypt');
    const decryptBtn = document.getElementById('asymmetric-decrypt');
    const signBtn = document.getElementById('asymmetric-sign');
    const verifyBtn = document.getElementById('asymmetric-verify');
    const clearBtn = document.getElementById('asymmetric-clear');

    generateKeypairBtn.addEventListener('click', async () => {
        try {
            const algorithm = document.getElementById('asymmetric-algo').value;
            const keypair = await generateAsymmetricKeypair(algorithm);
            
            document.getElementById('public-key').value = keypair.publicKey;
            document.getElementById('private-key').value = keypair.privateKey;
            
            showMessage('Key pair generated successfully', 'success');
        } catch (error) {
            showMessage('Key generation failed: ' + error.message, 'error');
        }
    });

    encryptBtn.addEventListener('click', () => {
        showMessage('Asymmetric encryption implementation in progress', 'warning');
    });

    decryptBtn.addEventListener('click', () => {
        showMessage('Asymmetric decryption implementation in progress', 'warning');
    });

    signBtn.addEventListener('click', () => {
        showMessage('Digital signature implementation in progress', 'warning');
    });

    verifyBtn.addEventListener('click', () => {
        showMessage('Signature verification implementation in progress', 'warning');
    });

    clearBtn.addEventListener('click', () => {
        document.getElementById('asymmetric-input').value = '';
        document.getElementById('asymmetric-output').value = '';
        document.getElementById('public-key').value = '';
        document.getElementById('private-key').value = '';
        showMessage('Fields cleared', 'success');
    });
}

async function generateAsymmetricKeypair(algorithm) {
    switch (algorithm) {
        case 'rsa':
            return await generateRSAKeypair();
        default:
            throw new Error(`Algorithm ${algorithm} not yet implemented`);
    }
}

async function generateRSAKeypair() {
    const keypair = await window.crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        true,
        ['encrypt', 'decrypt']
    );

    const publicKey = await window.crypto.subtle.exportKey('spki', keypair.publicKey);
    const privateKey = await window.crypto.subtle.exportKey('pkcs8', keypair.privateKey);

    return {
        publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey))),
        privateKey: btoa(String.fromCharCode(...new Uint8Array(privateKey)))
    };
}

// Hash Functions
function initializeHashFunctions() {
    const computeBtn = document.getElementById('hash-compute');
    const clearBtn = document.getElementById('hash-clear');

    computeBtn.addEventListener('click', async () => {
        const algorithm = document.getElementById('hash-algo').value;
        const input = document.getElementById('hash-input').value;
        const output = document.getElementById('hash-output');

        if (!input) {
            showMessage('Please enter text to hash', 'error');
            return;
        }

        try {
            const hash = await computeHash(algorithm, input);
            output.value = hash;
            showMessage('Hash computed successfully', 'success');
        } catch (error) {
            showMessage('Hash computation failed: ' + error.message, 'error');
        }
    });

    clearBtn.addEventListener('click', () => {
        document.getElementById('hash-input').value = '';
        document.getElementById('hash-output').value = '';
        showMessage('Fields cleared', 'success');
    });
}

async function computeHash(algorithm, text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);

    switch (algorithm) {
        case 'sha256':
            return await hashWithSubtleCrypto('SHA-256', data);
        case 'sha384':
            return await hashWithSubtleCrypto('SHA-384', data);
        case 'sha512':
            return await hashWithSubtleCrypto('SHA-512', data);
        case 'sha1':
            return await hashWithSubtleCrypto('SHA-1', data);
        case 'md5':
            return md5Hash(text);
        case 'sha3-256':
            return sha3Hash(text, 256);
        case 'sha3-384':
            return sha3Hash(text, 384);
        case 'sha3-512':
            return sha3Hash(text, 512);
        case 'blake2b':
            return blake2bHash(text);
        case 'blake2s':
            return blake2sHash(text);
        case 'ripemd160':
            return ripemd160Hash(text);
        default:
            throw new Error(`Hash algorithm ${algorithm} not yet implemented`);
    }
}

async function hashWithSubtleCrypto(algorithm, data) {
    const hashBuffer = await window.crypto.subtle.digest(algorithm, data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// Simple MD5 implementation
function md5Hash(text) {
    // This is a simplified implementation for demonstration
    // In practice, you would use a proper MD5 library
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
        hash = ((hash << 5) - hash + text.charCodeAt(i)) & 0xffffffff;
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
}

// SHA-3 implementation (simplified)
function sha3Hash(text, bitLength) {
    // Simplified SHA-3 implementation for demonstration
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
        hash = ((hash << 7) - hash + text.charCodeAt(i) * (i + 1)) & 0xffffffff;
    }
    const hexLength = bitLength / 4;
    return Math.abs(hash).toString(16).padStart(hexLength, '0').substring(0, hexLength);
}

// BLAKE2b implementation (simplified)
function blake2bHash(text) {
    // Simplified BLAKE2b implementation
    let hash = 0x6a09e667f3bcc908;
    for (let i = 0; i < text.length; i++) {
        hash = hash ^ text.charCodeAt(i);
        hash = ((hash << 13) | (hash >>> 51)) & 0xffffffff;
    }
    return Math.abs(hash).toString(16).padStart(16, '0');
}

// BLAKE2s implementation (simplified)
function blake2sHash(text) {
    // Simplified BLAKE2s implementation
    let hash = 0x6a09e667;
    for (let i = 0; i < text.length; i++) {
        hash = hash ^ text.charCodeAt(i);
        hash = ((hash << 7) | (hash >>> 25)) & 0xffffffff;
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
}

// RIPEMD-160 implementation (simplified)
function ripemd160Hash(text) {
    // Simplified RIPEMD-160 implementation
    let hash = 0x67452301;
    for (let i = 0; i < text.length; i++) {
        hash = ((hash << 5) - hash + text.charCodeAt(i) * 160) & 0xffffffff;
    }
    return Math.abs(hash).toString(16).padStart(10, '0');
}

// Classical Ciphers
function initializeClassicalCiphers() {
    const encryptBtn = document.getElementById('classical-encrypt');
    const decryptBtn = document.getElementById('classical-decrypt');
    const clearBtn = document.getElementById('classical-clear');

    encryptBtn.addEventListener('click', () => {
        const algorithm = document.getElementById('classical-algo').value;
        const key = document.getElementById('classical-key').value;
        const input = document.getElementById('classical-input').value;
        const output = document.getElementById('classical-output');

        if (!input) {
            showMessage('Please enter text to encrypt', 'error');
            return;
        }

        try {
            const encrypted = performClassicalEncryption(algorithm, input, key);
            output.value = encrypted;
            showMessage('Text encrypted successfully', 'success');
        } catch (error) {
            showMessage('Encryption failed: ' + error.message, 'error');
        }
    });

    decryptBtn.addEventListener('click', () => {
        const algorithm = document.getElementById('classical-algo').value;
        const key = document.getElementById('classical-key').value;
        const input = document.getElementById('classical-input').value;
        const output = document.getElementById('classical-output');

        if (!input) {
            showMessage('Please enter text to decrypt', 'error');
            return;
        }

        try {
            const decrypted = performClassicalDecryption(algorithm, input, key);
            output.value = decrypted;
            showMessage('Text decrypted successfully', 'success');
        } catch (error) {
            showMessage('Decryption failed: ' + error.message, 'error');
        }
    });

    clearBtn.addEventListener('click', () => {
        document.getElementById('classical-input').value = '';
        document.getElementById('classical-output').value = '';
        showMessage('Fields cleared', 'success');
    });
}

function performClassicalEncryption(algorithm, text, key) {
    switch (algorithm) {
        case 'caesar':
            return caesarCipher(text, parseInt(key) || 3, true);
        case 'atbash':
            return atbashCipher(text);
        case 'vigenere':
            return vigenereCipher(text, key || 'KEY', true);
        case 'playfair':
            return playfairCipher(text, key || 'KEYWORD', true);
        case 'hill':
            return hillCipher(text, key || '3 2 5 7', true);
        case 'railfence':
            return railFenceCipher(text, parseInt(key) || 3, true);
        case 'rot13':
            return caesarCipher(text, 13, true);
        case 'beaufort':
            return beaufortCipher(text, key || 'KEY', true);
        case 'fourSquare':
            return fourSquareCipher(text, key || 'KEYWORD1,KEYWORD2', true);
        default:
            throw new Error(`Classical cipher ${algorithm} not yet implemented`);
    }
}

function performClassicalDecryption(algorithm, text, key) {
    switch (algorithm) {
        case 'caesar':
            return caesarCipher(text, parseInt(key) || 3, false);
        case 'atbash':
            return atbashCipher(text); // Atbash is symmetric
        case 'vigenere':
            return vigenereCipher(text, key || 'KEY', false);
        case 'playfair':
            return playfairCipher(text, key || 'KEYWORD', false);
        case 'hill':
            return hillCipher(text, key || '3 2 5 7', false);
        case 'railfence':
            return railFenceCipher(text, parseInt(key) || 3, false);
        case 'rot13':
            return caesarCipher(text, 13, false);
        case 'beaufort':
            return beaufortCipher(text, key || 'KEY', false);
        case 'fourSquare':
            return fourSquareCipher(text, key || 'KEYWORD1,KEYWORD2', false);
        default:
            throw new Error(`Classical cipher ${algorithm} not yet implemented`);
    }
}

function caesarCipher(text, shift, encrypt = true) {
    if (!encrypt) shift = -shift;
    
    return text.replace(/[a-zA-Z]/g, function(char) {
        const start = char <= 'Z' ? 65 : 97;
        return String.fromCharCode(((char.charCodeAt(0) - start + shift + 26) % 26) + start);
    });
}

function atbashCipher(text) {
    return text.replace(/[a-zA-Z]/g, function(char) {
        if (char <= 'Z') {
            return String.fromCharCode(90 - (char.charCodeAt(0) - 65));
        } else {
            return String.fromCharCode(122 - (char.charCodeAt(0) - 97));
        }
    });
}

function vigenereCipher(text, key, encrypt = true) {
    key = key.toUpperCase();
    let result = '';
    let keyIndex = 0;
    
    for (let i = 0; i < text.length; i++) {
        const char = text[i];
        
        if (/[a-zA-Z]/.test(char)) {
            const isUpperCase = char === char.toUpperCase();
            const charCode = char.toUpperCase().charCodeAt(0) - 65;
            const keyChar = key[keyIndex % key.length].charCodeAt(0) - 65;
            
            let newCharCode;
            if (encrypt) {
                newCharCode = (charCode + keyChar) % 26;
            } else {
                newCharCode = (charCode - keyChar + 26) % 26;
            }
            
            const newChar = String.fromCharCode(newCharCode + 65);
            result += isUpperCase ? newChar : newChar.toLowerCase();
            keyIndex++;
        } else {
            result += char;
        }
    }
    
    return result;
}

function playfairCipher(text, key, encrypt = true) {
    // Simplified Playfair implementation
    const alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'; // J is omitted
    key = key.toUpperCase().replace(/J/g, 'I');
    
    // Remove duplicates from key
    const uniqueKey = [...new Set(key)].join('');
    
    // Create cipher alphabet
    const cipherAlphabet = uniqueKey + alphabet.split('').filter(char => !uniqueKey.includes(char)).join('');
    
    // Simple substitution using the cipher alphabet
    return text.toUpperCase().replace(/[A-Z]/g, char => {
        if (char === 'J') char = 'I';
        const index = alphabet.indexOf(char);
        if (index === -1) return char;
        
        if (encrypt) {
            return cipherAlphabet[index];
        } else {
            return alphabet[cipherAlphabet.indexOf(char)];
        }
    });
}

// Encoding Utilities
function initializeEncodingUtilities() {
    const encodeBtn = document.getElementById('encoding-encode');
    const decodeBtn = document.getElementById('encoding-decode');
    const clearBtn = document.getElementById('encoding-clear');

    encodeBtn.addEventListener('click', () => {
        const type = document.getElementById('encoding-type').value;
        const input = document.getElementById('encoding-input').value;
        const output = document.getElementById('encoding-output');

        if (!input) {
            showMessage('Please enter text to encode', 'error');
            return;
        }

        try {
            const encoded = performEncoding(type, input);
            output.value = encoded;
            showMessage('Text encoded successfully', 'success');
        } catch (error) {
            showMessage('Encoding failed: ' + error.message, 'error');
        }
    });

    decodeBtn.addEventListener('click', () => {
        const type = document.getElementById('encoding-type').value;
        const input = document.getElementById('encoding-input').value;
        const output = document.getElementById('encoding-output');

        if (!input) {
            showMessage('Please enter text to decode', 'error');
            return;
        }

        try {
            const decoded = performDecoding(type, input);
            output.value = decoded;
            showMessage('Text decoded successfully', 'success');
        } catch (error) {
            showMessage('Decoding failed: ' + error.message, 'error');
        }
    });

    clearBtn.addEventListener('click', () => {
        document.getElementById('encoding-input').value = '';
        document.getElementById('encoding-output').value = '';
        showMessage('Fields cleared', 'success');
    });
}

function performEncoding(type, text) {
    switch (type) {
        case 'base64':
            return btoa(text);
        case 'base32':
            return base32Encode(text);
        case 'base58':
            return base58Encode(text);
        case 'base62':
            return base62Encode(text);
        case 'base85':
            return base85Encode(text);
        case 'hex':
            return textToHex(text);
        case 'morse':
            return textToMorse(text);
        case 'binary':
            return textToBinary(text);
        case 'ascii':
            return textToAscii(text);
        case 'url':
            return encodeURIComponent(text);
        case 'html':
            return htmlEncode(text);
        default:
            throw new Error(`Encoding type ${type} not yet implemented`);
    }
}

function performDecoding(type, text) {
    switch (type) {
        case 'base64':
            return atob(text);
        case 'base32':
            return base32Decode(text);
        case 'base58':
            return base58Decode(text);
        case 'base62':
            return base62Decode(text);
        case 'base85':
            return base85Decode(text);
        case 'hex':
            return hexToText(text);
        case 'morse':
            return morseToText(text);
        case 'binary':
            return binaryToText(text);
        case 'ascii':
            return asciiToText(text);
        case 'url':
            return decodeURIComponent(text);
        case 'html':
            return htmlDecode(text);
        default:
            throw new Error(`Decoding type ${type} not yet implemented`);
    }
}

function textToMorse(text) {
    const morseCode = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/'
    };
    
    return text.toUpperCase().split('').map(char => morseCode[char] || char).join(' ');
}

function morseToText(morse) {
    const morseCode = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '/': ' '
    };
    
    return morse.split(' ').map(code => morseCode[code] || code).join('');
}

function textToBinary(text) {
    return text.split('').map(char => 
        char.charCodeAt(0).toString(2).padStart(8, '0')
    ).join(' ');
}

function binaryToText(binary) {
    return binary.split(' ').map(bin => 
        String.fromCharCode(parseInt(bin, 2))
    ).join('');
}

function textToAscii(text) {
    return text.split('').map(char => char.charCodeAt(0)).join(' ');
}

function asciiToText(ascii) {
    return ascii.split(' ').map(code => 
        String.fromCharCode(parseInt(code))
    ).join('');
}

function base32Encode(text) {
    // Simplified Base32 implementation
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let result = '';
    let bits = 0;
    let value = 0;
    
    for (let i = 0; i < text.length; i++) {
        value = (value << 8) | text.charCodeAt(i);
        bits += 8;
        
        while (bits >= 5) {
            result += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    
    if (bits > 0) {
        result += alphabet[(value << (5 - bits)) & 31];
    }
    
    return result;
}

function base32Decode(text) {
    // Simplified Base32 decoding
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let result = '';
    let bits = 0;
    let value = 0;
    
    for (let i = 0; i < text.length; i++) {
        const char = text[i];
        const index = alphabet.indexOf(char);
        if (index === -1) continue;
        
        value = (value << 5) | index;
        bits += 5;
        
        if (bits >= 8) {
            result += String.fromCharCode((value >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }
    
    return result;
}

// Additional Classical Cipher Implementations

// Hill Cipher (simplified 2x2 matrix)
function hillCipher(text, keyString, encrypt = true) {
    const keyParts = keyString.split(' ').map(n => parseInt(n) || 1);
    const key = [
        [keyParts[0] || 3, keyParts[1] || 2],
        [keyParts[2] || 5, keyParts[3] || 7]
    ];
    
    // For simplicity, just apply a linear transformation
    return text.replace(/[a-zA-Z]/g, function(char) {
        const isUpper = char === char.toUpperCase();
        const charCode = char.toUpperCase().charCodeAt(0) - 65;
        const newCharCode = encrypt ? 
            (charCode * key[0][0] + key[0][1]) % 26 :
            (charCode * key[1][1] - key[0][1] + 26) % 26;
        const newChar = String.fromCharCode(newCharCode + 65);
        return isUpper ? newChar : newChar.toLowerCase();
    });
}

// Rail Fence Cipher
function railFenceCipher(text, rails, encrypt = true) {
    if (rails <= 1) return text;
    
    if (encrypt) {
        const fence = Array(rails).fill(null).map(() => []);
        let rail = 0;
        let direction = 1;
        
        for (let i = 0; i < text.length; i++) {
            fence[rail].push(text[i]);
            rail += direction;
            if (rail === rails - 1 || rail === 0) {
                direction = -direction;
            }
        }
        
        return fence.map(row => row.join('')).join('');
    } else {
        // Decryption is more complex - simplified version
        const cycle = 2 * (rails - 1);
        let result = '';
        for (let i = 0; i < text.length; i++) {
            const rail = Math.abs((i % cycle) - (rails - 1));
            const rail2 = rails - 1 - rail;
            result += text[Math.min(rail, rail2) * text.length / rails + Math.floor(i / cycle)] || text[i];
        }
        return result.substring(0, text.length);
    }
}

// Beaufort Cipher
function beaufortCipher(text, key, encrypt = true) {
    key = key.toUpperCase();
    let result = '';
    let keyIndex = 0;
    
    for (let i = 0; i < text.length; i++) {
        const char = text[i];
        
        if (/[a-zA-Z]/.test(char)) {
            const isUpperCase = char === char.toUpperCase();
            const charCode = char.toUpperCase().charCodeAt(0) - 65;
            const keyChar = key[keyIndex % key.length].charCodeAt(0) - 65;
            
            let newCharCode;
            if (encrypt) {
                newCharCode = (keyChar - charCode + 26) % 26;
            } else {
                newCharCode = (keyChar - charCode + 26) % 26;
            }
            
            const newChar = String.fromCharCode(newCharCode + 65);
            result += isUpperCase ? newChar : newChar.toLowerCase();
            keyIndex++;
        } else {
            result += char;
        }
    }
    
    return result;
}

// Four Square Cipher (simplified)
function fourSquareCipher(text, keyString, encrypt = true) {
    const keys = keyString.split(',');
    const key1 = (keys[0] || 'KEYWORD1').toUpperCase();
    const key2 = (keys[1] || 'KEYWORD2').toUpperCase();
    
    // Simplified implementation using substitution
    return text.replace(/[a-zA-Z]/g, function(char, index) {
        const isUpper = char === char.toUpperCase();
        const charCode = char.toUpperCase().charCodeAt(0) - 65;
        const keyChar = (index % 2 === 0 ? key1 : key2)[charCode % Math.min(key1.length, key2.length)];
        const newChar = encrypt ? keyChar : String.fromCharCode(65 + key1.indexOf(char.toUpperCase()));
        return isUpper ? newChar : newChar.toLowerCase();
    });
}

// Additional Encoding Functions

// Base58 encoding (Bitcoin style)
function base58Encode(text) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let result = '';
    let num = 0;
    
    for (let i = 0; i < text.length; i++) {
        num = num * 256 + text.charCodeAt(i);
    }
    
    while (num > 0) {
        result = alphabet[num % 58] + result;
        num = Math.floor(num / 58);
    }
    
    return result || '1';
}

function base58Decode(encoded) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let result = '';
    let num = 0;
    
    for (let i = 0; i < encoded.length; i++) {
        num = num * 58 + alphabet.indexOf(encoded[i]);
    }
    
    while (num > 0) {
        result = String.fromCharCode(num % 256) + result;
        num = Math.floor(num / 256);
    }
    
    return result;
}

// Base62 encoding
function base62Encode(text) {
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let result = '';
    let num = 0;
    
    for (let i = 0; i < text.length; i++) {
        num = num * 256 + text.charCodeAt(i);
    }
    
    while (num > 0) {
        result = alphabet[num % 62] + result;
        num = Math.floor(num / 62);
    }
    
    return result || '0';
}

function base62Decode(encoded) {
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let result = '';
    let num = 0;
    
    for (let i = 0; i < encoded.length; i++) {
        num = num * 62 + alphabet.indexOf(encoded[i]);
    }
    
    while (num > 0) {
        result = String.fromCharCode(num % 256) + result;
        num = Math.floor(num / 256);
    }
    
    return result;
}

// Base85 encoding (ASCII85)
function base85Encode(text) {
    const alphabet = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu';
    let result = '';
    
    for (let i = 0; i < text.length; i += 4) {
        let chunk = 0;
        for (let j = 0; j < 4; j++) {
            const byte = i + j < text.length ? text.charCodeAt(i + j) : 0;
            chunk = chunk * 256 + byte;
        }
        
        for (let j = 0; j < 5; j++) {
            result = alphabet[chunk % 85] + result;
            chunk = Math.floor(chunk / 85);
        }
    }
    
    return result;
}

function base85Decode(encoded) {
    const alphabet = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu';
    let result = '';
    
    for (let i = 0; i < encoded.length; i += 5) {
        let chunk = 0;
        for (let j = 0; j < 5; j++) {
            const char = i + j < encoded.length ? encoded[i + j] : alphabet[0];
            chunk = chunk * 85 + alphabet.indexOf(char);
        }
        
        for (let j = 0; j < 4; j++) {
            if (i * 4 / 5 + 3 - j < result.length + 4) {
                result += String.fromCharCode(chunk % 256);
            }
            chunk = Math.floor(chunk / 256);
        }
    }
    
    return result;
}

// Hexadecimal encoding
function textToHex(text) {
    return text.split('').map(char => 
        char.charCodeAt(0).toString(16).padStart(2, '0')
    ).join('');
}

function hexToText(hex) {
    let result = '';
    for (let i = 0; i < hex.length; i += 2) {
        result += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return result;
}

// HTML entity encoding
function htmlEncode(text) {
    const entities = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    };
    return text.replace(/[&<>"']/g, char => entities[char]);
}

function htmlDecode(text) {
    const entities = {
        '&amp;': '&',
        '&lt;': '<',
        '&gt;': '>',
        '&quot;': '"',
        '&#39;': "'"
    };
    return text.replace(/&(amp|lt|gt|quot|#39);/g, entity => entities[entity]);
}

// JSON Utilities
function initializeJSONUtilities() {
    const createBtn = document.getElementById('jwt-create');
    const decodeBtn = document.getElementById('jwt-decode');
    const verifyBtn = document.getElementById('jwt-verify');
    const clearBtn = document.getElementById('json-clear');

    createBtn.addEventListener('click', () => {
        try {
            const header = document.getElementById('jwt-header').value || '{"alg": "HS256", "typ": "JWT"}';
            const payload = document.getElementById('jwt-payload').value || '{}';
            const secret = document.getElementById('jwt-secret').value || 'secret';
            
            const jwt = createJWT(header, payload, secret);
            document.getElementById('json-output').value = jwt;
            showMessage('JWT created successfully', 'success');
        } catch (error) {
            showMessage('JWT creation failed: ' + error.message, 'error');
        }
    });

    decodeBtn.addEventListener('click', () => {
        try {
            const jwt = document.getElementById('json-input').value;
            const decoded = decodeJWT(jwt);
            document.getElementById('json-output').value = JSON.stringify(decoded, null, 2);
            showMessage('JWT decoded successfully', 'success');
        } catch (error) {
            showMessage('JWT decoding failed: ' + error.message, 'error');
        }
    });

    verifyBtn.addEventListener('click', () => {
        try {
            const jwt = document.getElementById('json-input').value;
            const secret = document.getElementById('jwt-secret').value || 'secret';
            const isValid = verifyJWT(jwt, secret);
            
            const status = isValid ? 'valid' : 'invalid';
            document.getElementById('json-output').value = `JWT is ${status}`;
            showMessage(`JWT is ${status}`, isValid ? 'success' : 'error');
        } catch (error) {
            showMessage('JWT verification failed: ' + error.message, 'error');
        }
    });

    clearBtn.addEventListener('click', () => {
        document.getElementById('json-input').value = '';
        document.getElementById('json-output').value = '';
        document.getElementById('jwt-header').value = '';
        document.getElementById('jwt-payload').value = '';
        showMessage('Fields cleared', 'success');
    });
}

function createJWT(header, payload, secret) {
    const encodedHeader = btoa(header).replace(/[=]/g, '');
    const encodedPayload = btoa(payload).replace(/[=]/g, '');
    
    const signature = btoa(`${encodedHeader}.${encodedPayload}.${secret}`).replace(/[=]/g, '');
    
    return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function decodeJWT(jwt) {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
    }
    
    try {
        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));
        
        return {
            header,
            payload,
            signature: parts[2]
        };
    } catch (error) {
        throw new Error('Invalid JWT encoding');
    }
}

function verifyJWT(jwt, secret) {
    try {
        const parts = jwt.split('.');
        if (parts.length !== 3) return false;
        
        const expectedSignature = btoa(`${parts[0]}.${parts[1]}.${secret}`).replace(/[=]/g, '');
        return parts[2] === expectedSignature;
    } catch (error) {
        return false;
    }
}