
from enum import Enum

class Status(Enum):
  RUN = 1
  BLOCKED_SEND = 2
  BLOCKED_RECV = 3
  DYING = 4

