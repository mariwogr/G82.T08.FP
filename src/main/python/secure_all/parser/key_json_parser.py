"""parser for input key files according to RF2"""

from secure_all.parser.json_parser import JsonParser

class KeyJsonParser(JsonParser):
    """parser for input key files containing a AccessKey request"""
    #pylint: disable=too-few-public-methods
    ACCESS_CODE = "AccessCode"
    DNI = "DNI"
    MAIL_LIST = "NotificationMail"
    _key_list =  [ ACCESS_CODE, DNI, MAIL_LIST ]
