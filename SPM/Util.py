#Assorted utilities

from .. import _debug, _debug_width

def log(msg):
  if not _debug:
    return
  msg = msg.strip()
  if len(msg) <= _debug_width:
    print(msg)
  else:
    print(msg[:(_debug_width-3)] + "...")

