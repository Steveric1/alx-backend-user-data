#!/usr/bin/env pyhon3
"""
Definition of _hash_password function
"""
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User
from uuid import uuid4


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


def generate_uuid() -> str:
    """
    method that generate uuid
    Return:
      str(uuid4())
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Method that take mandatory email and password string arguments
        and return a User object.
        Args:
           - email(str): user's email
           - password(str): user's password

        Return:
            user object
        Raises:
            - ValueError: if user already exist with passed email.
        """
        try:
            usr = self._db.find_user_by(email=email)
            if usr.email == email:
                raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            passwd = _hash_password(password)
            user = User(email=email, hashed_password=passwd)
            session = self._db._session
            session.add(user)
            session.commit()
            return user
        except ValueError:
            raise

    def valid_login(self, email: str, password: str) -> bool:
        """
        method to implement login
        Args:
           - email(str): user's email
           - password(str): user's password
        Return
           Bool
        """
        try:
            user = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
                return True
        except NoResultFound:
            return False
