from enum import Enum

#Tickets and Rights(Enum)

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
      assert len(right) == 3
      assert right[0:2] == "T/"
      self.right = Right[right[2]]
      
  def adapt_ticket(self):
    return repr(self)

  @staticmethod
  def convert_ticket(string):
    if isinstance(string,Ticket):
      return string
    return Ticket(string)

  def __repr__(self):
    return "T/%s" % str(self.right.name)

