"""module for the attribute class (abstract)"""

import re

from secure_all.exception.access_management_exception import AccessManagementException

class Attribute():
    #pylint: disable=too-few-public-methods
    """Class Attribute for respresenting a generic attribute"""

    #Default value
    _attr_value = ""
    """regex validation pattern"""
    _validation_pattern = r""
    """Default error message"""
    _error_message = ""

    def _validate(self, attr_value):
        if not isinstance(attr_value, str):
            raise AccessManagementException(self._error_message)
        # print(self._validation_pattern, attr_value)
        # print(re.fullmatch(self._validation_pattern, attr_value))
        if not re.fullmatch(self._validation_pattern, attr_value):
            raise AccessManagementException(self._error_message)
        return attr_value

    @property
    def value(self):
        """Getter for _attr_value"""
        return self._attr_value

    @value.setter
    def value(self, input_value):
        self._attr_value = input_value
