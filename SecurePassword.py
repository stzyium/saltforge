#!/usr/bin/env python3

# This module implements a secure password storage and verification system using
# cryptographic best practices including salting and hashing techniques.

# Key Features:
# - Password salting to prevent rainbow table attacks
# - Support for multiple hashing algorithms (SHA-256, SHA-512, etc.)
# - Two-level security system with PBKDF2 key derivation
# - Configurable salt length and iteration count

# Author: stzyium@github
# License: MIT
# Version: 1-end

# Dependencies:
# - hashlib: For cryptographic hash functions
# - random: For secure salt generation
# - string: For character set management
# - typing: For type hints


"""
Data Dictionary Structure
------------------------
The Data dictionary stores essential information for password management:

Keys and their descriptions:
- Na (str): The generated salt string used for password hashing
- TxL (int): Maximum allowed length limit for the input text/password
- NaL (int): Length of the generated salt
- Hash (str): The final hashed value of the password
- Algorithm (str): The hashing algorithm used (e.g., 'sha256')
- Secure (int): Security level used (1 or 2) for password hashing
"""

import hashlib, _hashlib
import random
import string
from typing import Literal

chars = ''.join(c for c in string.printable if c not in f",.;:'\"`{string.whitespace} ")
Data = {}
ALGORITHMS: set[str] = hashlib.algorithms_guaranteed

class Salting:
    """
    This class provides methods for adding salt to a given text, enhancing its security before hashing.
    """
    @staticmethod
    def MixSalt(text: str, limit: int = 32, saltQ: int = 64) -> tuple[str, str]:
        """
        Mixes a random salt with the input text to protect against rainbow table attacks.

        Args:
            text (str): The text to be salted.
            limit (int, optional): The maximum length of the text. Defaults to 32.
            saltQ (int, optional): The length of the salt. Defaults to 64.

        Returns:
            tuple[str, str]: A tuple containing the salted text and the salt used.

        Raises:
            Exception: If the input text exceeds the specified length limit.
        """
        global Data
        if len(text) > limit:
            raise Exception("Input longer than {} isn't allowed".format(limit))
        salt = ''.join(random.choices(chars, k=saltQ))
        Data.update({"Na": salt, "TxL": limit, "NaL": saltQ})
        count = 0
        constructedString = ""
        for i in range(len(text)):
            if len(text) > saltQ and count >= saltQ:
                constructedString += text[count:]
                break
            constructedString += salt[count] + text[count]
            count += 1
        if saltQ > len(text) and count <= saltQ:
            constructedString += salt[count:]
        return constructedString, salt
    @staticmethod
    def CheckSalt(**kwargs) -> str:
        """
        Reconstructs the salted text given the salt and original text details.

        Args:
            **kwargs: Keyword arguments containing 'Na' (salt), 'text', 'TxL' (text length limit), and 'NaL' (salt length).

        Returns:
            str: The reconstructed salted text.
        """
        count = 0
        constructedString = ""
        salt = kwargs["Na"]
        text, limit, saltQ = kwargs['text'], kwargs['TxL'], kwargs['NaL']
        for i in range(len(text)):
            if len(text) > saltQ and count >= saltQ:
                constructedString += text[count:]
                break
            constructedString += salt[count] + text[count]
            count += 1
        if saltQ > len(text) and count <= saltQ:
            constructedString += salt[count:]
        return constructedString
class Hashing:
    """
    This class provides methods for hashing text using various algorithms.
    """
    @staticmethod
    def hash(text: str, algorithm: str, Na: str = None, _iter: int = 100000) -> _hashlib.HASH:
        """
        Hashes the given text using the specified algorithm.

        Args:
            text (str): The text to be hashed.
            algorithm (str): The hashing algorithm to use (e.g., 'sha256').
            Na (str, optional): Salt value to use for key derivation. Defaults to None.
            _iter (int, optional): Number of iterations for the pbkdf2_hmac algorithm. Defaults to 100000.

        Returns:
            _hashlib.HASH: The hashed object.

        Raises:
            ValueError: If the specified algorithm is not supported.
        """
        if not algorithm.lower() in ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported: {str(*ALGORITHMS)}")
        if Na:
            return hashlib.new(algorithm, hashlib.pbkdf2_hmac(algorithm, text.encode(), Na[1].encode(), _iter))
        return getattr(hashlib, algorithm.lower())(text.encode())
            
def Store(text: str, algorithm: str = 'sha256', SecurityLevel: Literal[1, 2] = 1, **kwargs):
    """
    Stores the hashed version of the given text using the specified algorithm and security level.

    Args:
        text (str): The text to be stored.
        algorithm (str, optional): The hashing algorithm to use. Defaults to 'sha256'.
        SecurityLevel (Literal[1, 2], optional): The security level to use. Defaults to 1.
        **kwargs: Additional keyword arguments.

    Raises:
        ValueError: If an invalid security level is provided.
    """
    global Data
    salted, rNa = Salting.MixSalt(text)
    match SecurityLevel:
        case 1:
            hashed = Hashing.hash(salted, algorithm)
        case 2:
            hashed = Hashing.hash(salted, algorithm, rNa)
        case _:
            raise ValueError("Invalid Security Level")
    Data.update({"Hash": hashed.hexdigest(), "Algorithm": algorithm, "Secure": SecurityLevel})
    
def Fetch(text: str, **kwargs) -> tuple:
    """
    Fetches and verifies the stored hash against the provided text.

    Args:
        text (str): The text to be verified.
        **kwargs: Additional keyword arguments.

    Returns:
        tuple: A tuple containing a status code (1 for success, 0 for failure) and a message.

    Raises:
        ValueError: If no stored data or hash is found.
    """
    if not kwargs:
        raise ValueError("No data found")
    
    algorithm = kwargs.get("algorithm", "sha256")
    storedHash = kwargs.get("Hash")
    if not storedHash:
        raise ValueError("No hash found in stored data")
    
    salted = Salting.CheckSalt(text=text, Na=kwargs["Na"], TxL=kwargs["TxL"], NaL=kwargs["NaL"])
    ComputedHash = Hashing.hash(salted, algorithm, Na=kwargs["Na"] if kwargs["Secure"] == 2 else None)
    
    if ComputedHash.hexdigest() == storedHash:
        return 1, "Password Matched!"
    else:
        return 0, "Authentication Failed"
    
def Test():
    """
    The main function to run the secure password storage and verification system.
    """
    print('\n🔐', " Secure Password System ", '🔐')
    print()
    password = input("🔑 Enter your password to store securely: ").strip()
    Store(password, algorithm='sha256', SecurityLevel=1)
    print("\n✅ [SUCCESS] Password securely hashed and stored!")

    print("\n📊", " Password Data Summary ", "📊")
    print(f"    🧂 {'Salt':<14} : {Data['Na']}")
    print(f"    🔐 {'Algorithm':<14} : {Data['Algorithm']}")
    print(f"    🛡️  {'Security Level':<14} : {Data['Secure']}")

    print("\n📋", " Full Data Details ", "📋")
    
    maxlength = max(len(key) for key in Data)
    for key, value in sorted(Data.items()):
        print(f"    🌐 {key:<{maxlength}} : {value}")

    print("\n")
    print("🔓 Password Verification 🔓\n")
    
    attempts = 3
    while attempts > 0:
        vpassword = input(f"Attempt {4 - attempts}/3 - Enter your password: ").strip()
        result = Fetch(vpassword, **Data)
        if result[0]:
            print(f"\n[ACCESS GRANTED] {result[1]} - Welcome!")
            break
        else:
            attempts -= 1
            if attempts > 0:
                print(f"[ACCESS DENIED] {result[1]} - {attempts} attempts remaining.")
            else:
                print(f"[ACCESS DENIED] {result[1]} - No attempts remaining.")

    print("=" * 50)


if __name__ == "__main__":
    Test()