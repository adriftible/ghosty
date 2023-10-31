"""
`ghosty` is a password authentication manager which supports both creating and storing passwords securely and efficiently.
"""
import bcrypt
import sqlite3
from attrs import define

@define
class auth:
    """
    The authorization (auth) class does the creation, authentication, and storing of passwords in a secure way.
    """
    db: str

    def encrypt(password: str):
        byte_pass = bytes(password, 'UTF-8')

        salt = bcrypt.gensalt()

        hash = bcrypt.hashpw(byte_pass, salt)

        return hash