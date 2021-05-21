"""Class for validating the keys"""
from secure_all.data.attributes.attribute import Attribute
from secure_all.exception.access_management_exception import AccessManagementException


class Reason(Attribute):
    """Class for validating the keys with a regex"""
    #pylint: disable=too-few-public-methods
    def __init__(self, attr_value):
        self._validation_pattern = r'^[A-Za-z0-9\s]+$'
        self._error_message = "reason invalid"
        self._attr_value = self._validate(attr_value)

    def _validate(self, attr_value):
        super()._validate(attr_value)
        if len(attr_value) not in range(1, 101):
            raise AccessManagementException(self._error_message)
        return attr_value
