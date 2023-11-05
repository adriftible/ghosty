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

    _db: str = "ghosty"

    # * Setup sqlite3 database connections.
    _conn = sqlite3.connect(f"{_db}.db")
    _c = _conn.cursor()

    try:
        _c.execute(
            """CREATE TABLE passwords (
                        id integer primary key auto increment
                        hash blob
                        )"""
        )
        _conn.commit()
        _conn.close()
    except sqlite3.OperationalError:
        pass

    def encrypt(self, password: str):
        """Encrypts a given password using bcrypt and stores it into a sqlite3 database with hashed version.

        Args:
            password (str): A password or variable to be encrypted.

        Returns:
            hash: Given outcome of hashing and salting.
        """
        # Convert string to bytes
        byte_pass = bytes(password, "UTF-8")

        # Prepare salt generation and generate hash byte version of password
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(byte_pass, salt)

        self._c.execute(f"INSERT INTO passwords VALUES ({str(hash, 'utf-8')})")
        self._conn.commit()

        return hash


data = auth("ghosty")
data.encrypt("Peoples")
