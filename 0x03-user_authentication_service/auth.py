#!/usr/bin/env python3
"""
Definition of _hash_password function
"""
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User
from uuid import uuid4
from typing import Optional, Union


def _hash_password(password: str) -> bytes:
    """
    Hashes a password string and returns it in bytes form
    Args:
        password (str): password in string format
    """
    passwd = password.encode('utf-8')
    return bcrypt.hashpw(passwd, bcrypt.gensalt())


def _generate_uuid() -> str:
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

    def create_session(self, email: str) -> Union[None, str]:
        """
        method to implement session
        Args:
           - email(str): user's email
        Return
            session ID
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            user.session_id = session_id
            self._db._session.commit()
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Optional[User]:
        """
        Method to implement the get user from session id
        Args:
            - session_id(str): session id

        Return:
            corresponding User or None
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """
        Method to destory a session by updating the corresponding
        user's session id to None.
        Args:
            - user_id(int): user's id
        Return:
            None
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except NoResultFound:
            raise ValueError

    def get_reset_password_token(self, email: str) -> str:
        """
        Method to reset password token
        Args:
           - email(str): user's email
        Return:
            return the token
        Raises:
            - ValueError: if user already exist with passed email.
        """
        try:
            user = self._db.find_user_by(email=email)
            token = _generate_uuid()
            user.reset_token = token
            self._db._session.commit()
            return token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Method to update password
        Args:
           - reset_token(str): user's reset_token
           - password(str): user's password
        Return:
            None
        Raises:
            - ValueError: if corresponding user does not exist
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        hpw = _hash_password(password)
        user.hashed_password = hpw
        user.reset_token = None
        self._db._session.commit()
