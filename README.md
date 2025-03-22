# Password Security System

A secure password hashing system that implements various cryptographic techniques to securely store and verify passwords.

## Overview

This Python-based password security system provides robust mechanisms for password storage and verification using industry-standard cryptographic algorithms. The system implements salting and hashing techniques to protect passwords from various attacks, including rainbow table attacks and brute force attempts.

## Features

- Multiple cryptographic algorithm support (SHA-256, SHA-512, etc.)
- Custom salting implementation for enhanced security
- Two security levels with different protection mechanisms
- Configurable salt length and password limits
- Simple interface for storing and verifying passwords

## Installation

```bash
# Clone the repository
git clone https://github.com/stzyium/secure-pasword-hashing password

# Navigate to the project directory
cd password
python SecurePassword.py
# No external dependencies required - uses standard Python libraries
```

## How It Works

### Salting Process

The system uses a custom salting mechanism that interleaves random characters with the password characters:

1. A random salt of configurable length is generated
2. The salt is interleaved with the password characters
3. The resulting string is hashed using the selected algorithm

This approach makes the system resilient against dictionary attacks and rainbow table attacks.

### Security Levels

The system supports two security levels:

1. **Level 1**: Basic salting and hashing
2. **Level 2**: Enhanced security using double salting and PBKDF2 (Password-Based Key Derivation Function 2)

### Password Verification

Password verification works by:
1. Reconstructing the salted password using the stored salt
2. Hashing the reconstructed password
3. Comparing the computed hash with the stored hash

## Usage Example

```python
from SecurePassword import Store, Fetch, Data

# Store a password
password = "MySecurePassword123"
Store(password, algorithm='sha256', SecurityLevel=2)

# Verify a password
password = "wrongAttemptedPassword"
result, message = Fetch(password, **Data)
if result:
    print("Authentication successful!")
else:
    print("Authentication failed!")
```

## API Reference

### `Store(text, algorithm='sha256', SecurityLevel=1, **kwargs)`

Stores a password securely using salting and hashing.

Parameters:
- `text` (str): The password to store
- `algorithm` (str, optional): Hashing algorithm to use. Default is 'sha256'
- `SecurityLevel` (int, optional): Security level (1 or 2). Default is 1

### `Fetch(text, **kwargs)`

Verifies a password against stored credentials.

Parameters:
- `text` (str): The password to verify
- `**kwargs`: Additional parameters including salt and stored hash

Returns:
- `tuple`: (status_code, message) where status_code is 1 for success, 0 for failure

### `Salting` class

Provides methods for salting and verifying salted passwords:
- `MixSalt(text, limit=32, saltQ=64)`: Creates a salted version of the input text
- `CheckSalt(**kwargs)`: Reconstructs a salted password for verification

### `Hashing` class

Provides methods for hashing passwords:
- `hash(text, algorithm, Na=None, _iter=100000)`: Hashes input text using specified algorithm

## Security Considerations

- The system uses built-in Python cryptographic functions which are well-tested
- Security Level 2 is recommended for sensitive applications
- Increase iterations for PBKDF2 for additional security (with performance trade-offs)
- Supported algorithms are from Python's hashlib.algorithms_guaranteed

## License

MIT License
```
© 2025 stzyium
```
