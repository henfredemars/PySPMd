from enum import Enum
from SPM.Util import log

#Tickets and Rights(Enum)

class BadTicketError(RuntimeError):
  def __init__(self,msg):
    super().__init__(msg)
    log("BadTicketError: " + msg)

class Right(Enum):
  t = 1
  g = 2
  r = 3
  w = 4

class Ticket:

  def __init__(self,right):
    if isinstance(right,Right):
      self.right = right
    else:
      if len(right) == 3 and right[0:2] == "T/":
        self.right = Right[right[2]]
      else:
        raise BadTicketError("Bad ticket format.")
      
  def adapt_ticket(self):
    return repr(self)

  @staticmethod
  def convert_ticket(string):
    if isinstance(string,Ticket):
      return string
    if isinstance(string,bytes):
      string = string.decode(encoding="UTF-8",errors="ignore")
    return Ticket(string)

  def __repr__(self):
    return "T/%s" % str(self.right.name)

