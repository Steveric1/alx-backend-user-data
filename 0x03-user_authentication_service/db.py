#!/usr/bin/env python3

"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from user import User

from user import Base


class DB:
    """
    DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Create a user object and save it to the database
        Args:
           - email(str): user's email address
           - hashed_password(str): user's password
        Return:
           created user object
        """
        new_user = User(email=email, hashed_password=hashed_password)
        session = self._session
        session.add(new_user)
        session.commit()
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """
        Method to find user by input arguments
        Args:
           - kwargs: keyword argument
        Return:
           The first row found in the users table as filtered
        Raises:
           NoResultFound: If no rows match the query
           InvalidRequestError: If there's an issue with the query
        """
        try:
            session = self._session
            user = session.query(User).filter_by(**kwargs).first()
            if user is None:
                raise NoResultFound
            return user
        except InvalidRequestError:
            raise

    def update_user(self, user_id, **kwargs):
        """
        Method to update user by arbitary keyword arguments
        Args:
           - kwargs: keyword arguments
           - user_id: user id
        Return:
            returns None
        Raise:
           - ValueError: if an argument that does not correspond to a user
           attribute is passed.
        """
        try:
            user_update = self.find_user_by(id=user_id)
        except NoResultFound:
            raise ValueError
        for k, v in kwargs.items():
            if hasattr(user_update, k):
                setattr(user_update, k, v)
            else:
                raise ValueError
        session = self._session
        session.commit()
