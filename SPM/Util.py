#Assorted utilities

from . import _debug, _debug_width

def log(msg):
  if not _debug:
    return
  msg = msg.strip()
  if len(msg) <= _debug_width:
    print(msg)
  else:
    print(msg[:(_debug_width-3)] + "...")

def chunks(l, n):
    n = max(1, n)
    return [l[i:i+n] for i in range(0, len(l), n)]
