class UserErrors(Exception):
    """
    Error Exception
    """

    def __init__(self, message=None, error_message=None, response_code=None):
        self.message = message if message else "Could Not Validate Credentials"
        self.error_message = error_message if error_message else ""
        self.response_code = response_code if response_code else 400
        self.type = "User Errors"


class ClientErrors(UserErrors):
    """
    When error occured because of user's response
    """

    def __init__(self, message=None, error_message=None, response_code=None):
        self.message = message if message else "All fields are required"
        self.error_message = error_message if error_message else ""
        self.response_code = response_code if response_code else 400
        self.type = "Client Errors"

class DatabaseErrors(UserErrors):
    """
    When error occured because of database issue
    """

    def __init__(self, message=None, error_message=None, response_code=None):
        self.message = message if message else "Some Database Issue. Try Again"
        self.error_message = error_message if error_message else ""
        self.response_code = response_code if response_code else 503
        self.type = "Database Errors"