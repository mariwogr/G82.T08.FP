"""Attribute representing the AccessCode rules"""
from .attribute import Attribute

class AccessCode(Attribute):
    """Class for validating the access code values in secure_all"""
    #pylint: disable=too-few-public-methods

    def __init__( self,attr_value ):
        self._validation_pattern =  r'[0-9a-f]{32}'
        self._error_message = "access code invalid"
        self._attr_value = self._validate(attr_value)
