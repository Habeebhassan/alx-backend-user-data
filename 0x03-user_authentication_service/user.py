#!/usr/bin/env python3
"""
A SQLALchemy model
"""
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

# Create a base class for declarative models
Base = declarative_base()

class User(Base):
    """
    SQLAlchemy model for the 'users' table. Represents a user with the following attributes:
    - id: Integer primary key, auto-incremented.
    - email: Non-nullable string to store the user's email address.
    - hashed_password: Non-nullable string to store the user's hashed password.
    - session_id: Nullable string to store the user's session ID.
    - reset_token: Nullable string to store the password reset token.
    """
    __tablename__ = 'users'  # Defines the table name

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    session_id = Column(String(255), nullable=True)
    reset_token = Column(String(255), nullable=True)

    def __repr__(self):
        """
        String representation of the User object for debugging purposes.
        """
        return f"<User(id={self.id}, email={self.email})>"
