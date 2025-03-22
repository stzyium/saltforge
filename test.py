from SecurePassword import Store, Fetch, Data

# Store a password
password = "MySecurePassword123"
Store(password, algorithm='sha256', SecurityLevel=2)

# Verify a password
result, message = Fetch("MySecurePassword123", **Data)
if result:
    print("Authentication successful!")
else:
    print("Authentication failed!")