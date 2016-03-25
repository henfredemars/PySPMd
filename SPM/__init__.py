#SPM Module Initialization File

__author__ = "James Birdsong"
__license__ = "MIT License"
__version__ = 0

_hash_size = 20
_ticket_size = 3

_login_delay = 3
_msg_size = 2048
_subject_size = 64
_password_size = 64
_salt_size = 32
_file_size = 256
_data_size = (_msg_size-(2+2+_hash_size))
_error_msg_size = (_msg_size-(2+_hash_size))
_hash_rounds = 2**4
_debug = True
_debug_width = 300

_lss_count = 31
_ls_count = 7

assert _msg_size / _subject_size >= _lss_count
assert _msg_size / _file_size >= _ls_count

#Take care when tuning these parameters so that all messages, including
# authentication tags, will fit within the allowed message size
