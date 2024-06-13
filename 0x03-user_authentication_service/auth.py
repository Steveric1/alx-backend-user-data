#!/usr/bin/env pyhon3
"""
Definition of _hash_password function
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """
    _hash_password - method that takes in a password string arguments
    and return bytes.
    Args:
       - password(str): password to encrypt
    Return:
        bytes
    """
    hashed_password = password.encode('utf-8')
    return bcrypt.hashpw(hashed_password, bcrypt.gensalt())
