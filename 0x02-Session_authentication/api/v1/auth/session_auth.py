#!/usr/bin/env python3

'''Create a class SessionAuth that inherits from Auth
'''
from .auth import Auth
from uuid import uuid4
from models.user import User

class SessionAuth(Auth):
    user_id_by_session_id = {}
    def create_session(self, user_id: str = None) -> str:
        '''creates a Session ID for a user_id
        '''
        if type(user_id ) is str:
            session_id = str(uuid4())
            self.user_id_by_session_id[session_id] = user_id
            return session_id
    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Retrieves the user id of the user associated with
        a given session id.
        """
        if type(session_id) is str:
            return self.user_id_by_session_id.get(session_id)
    def current_user(self, request=None) -> User:
        """Retrieves the user associated with the request.
        """
        user_id = self.user_id_for_session_id(self.session_cookie(request))
        return User.get(user_id)


