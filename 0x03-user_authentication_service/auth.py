#!/usr/bin/env python3
"""A module for authentication-related routines.
"""
import bcrypt

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Hashes a password.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

