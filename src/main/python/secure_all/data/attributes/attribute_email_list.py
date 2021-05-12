"""Class for validating the email list"""
from secure_all.data.attributes.attribute import Attribute
from secure_all.data.attributes.attribute_email import Email
from secure_all.exception.access_management_exception import AccessManagementException

class EmailList(Attribute):
    """Class for validating the email list"""
    #pylint: disable=too-few-public-methods,super-init-not-called

    def __init__( self,attr_value ):
        self._error_message = "JSON Decode Error - Email list invalid"
        self._attr_value = self._validate(attr_value)


    def _validate(self, attr_value):
        """overrides the validate method for managing the input as a list of emails"""
        email_list = []
        for email in attr_value:
            email_list.append(Email(email).value)
        if len(email_list) < 1 or len(email_list) > 5:
            raise AccessManagementException(self._error_message)
        return email_list
