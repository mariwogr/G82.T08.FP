"""Class for validating the full name"""
from secure_all.data.attributes.attribute import Attribute
class FullName(Attribute):
    """Class for validating the full name with a regex"""
    #pylint: disable=too-few-public-methods

    def __init__( self,attr_value ):
        self._validation_pattern =  r'^[A-Za-z0-9]+(\s[A-Za-z0-9]+)+'
        self._error_message = "Invalid full name"
        self._attr_value = self._validate(attr_value)
