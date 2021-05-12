"""Attribute class for validating emails"""

from secure_all.data.attributes.attribute import Attribute

class Email(Attribute):
    """Class for validating emails according to a regex"""
    #pylint: disable=too-few-public-methods
    def __init__( self,attr_value ):
        self._validation_pattern =   r'^[a-z0-9]+[\._]?[a-z0-9]+[@](\w+[.])+\w{2,3}$'
        self._error_message = "Email invalid"
        self._attr_value = self._validate(attr_value)
