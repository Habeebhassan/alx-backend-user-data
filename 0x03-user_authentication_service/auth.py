#!/usr/bin/env python3
"""
Authentication System

This module provides utility functions
and a class to handle user
registration, authentication, session management,
and password reset functionality using
bcrypt for password hashing and
UUIDs for session and token generation.

Modules:
    - bcrypt: Provides password hashing functionality.
    - uuid4: Generates unique session tokens.
    - sqlalchemy.orm.exc.NoResultFound: Handles cases where
    no user is found in the database.
    - DB: Custom database interaction class.
    - User: Custom user model class.

Functions:
    - _hash_password(password: str) -> bytes: 
      Hashes a password using bcrypt
      and returns it in bytes.
    - _generate_uuid() -> str: Generates a
      UUID and returns its string.
"""

import bcrypt
from uuid import uuid4
from sqlalchemy.orm.exc import NoResultFound
from typing import TypeVar, Union
from db import DB
from user import User

U = TypeVar('U', bound=User)


def _hash_password(password: str) -> bytes:
    """
    Hashes a password string
    and returns it as bytes.
    
    Args:
        password (str): The password 
        to be hashed in string format.

    Returns:
        bytes: The hashed password.
    """
    passwd = password.encode('utf-8')
    return bcrypt.hashpw(passwd, bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Generates a UUID and returns
    its string representation.
    
    Returns:
        str: The generated UUID.
    """
    return str(uuid4())


class Auth:
    """
    The Auth class handles user
    authentication-related operations such as
    user registration, login validation,
    session management, and password reset.

    It interacts with a database
    to store and retrieve user information.
    """

    def __init__(self) -> None:
        """
        Initializes the Auth instance
        by setting up a database connection.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user with
        the provided email and password.
        
        Raises ValueError if a user
        with the given email already exists.
        
        Args:
            email (str): The email
            address of the new user.
            password (str): The new user's password.

        Returns:
            User: The newly created user.
        
        Raises:
            ValueError: If a user
            with the email already exists.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed = _hash_password(password)
            usr = self._db.add_user(email, hashed)
            return usr
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates user login credentials
        by checking email and password.
        
        Args:
            email (str): User's email address.
            password (str): User's password.

        Returns:
            bool: True if valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        user_password = user.hashed_password
        passwd = password.encode("utf-8")
        return bcrypt.checkpw(passwd, user_password)

    def create_session(self, email: str) -> Union[None, str]:
        """
        Creates a session ID for
        an existing user and updates the session.
        
        Args:
            email (str): The user's email.

        Returns:
            Union[None, str]: The session ID
            if user exists, otherwise None.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[None, U]:
        """
        Retrieves a user based on
        the provided session ID.
        
        Args:
            session_id (str): Session ID.

        Returns:
            Union[None, User]: User if found,
            otherwise None.
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
        Terminates a user's session by
        setting session_id to None.
        
        Args:
            user_id (int): The ID of the user.

        Returns:
            None
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """
        Generates and returns a password
        reset token for the user.
        
        Args:
            email (str): The user's email.

        Returns:
            str: The reset token.

        Raises:
            ValueError: If no user
            is found with the given email.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError(f"No user found with email {email}")

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates a user's password using
        the provided reset token.
        
        Args:
            reset_token (str): Reset token for password change.
            password (str): The new password.

        Raises:
            ValueError: If the reset token
            is invalid or user not found.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token")

        hashed = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed, reset_token=None)
