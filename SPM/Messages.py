from Util import log

from .. import _min_msg_size

#Messages

class BadMessageError(RuntimeError):
  def __init__(self,message):
    super().message = message
    log("BadMessageError: " + message)

class MessageStrategy:

  strategies = dict()

  def __init__(self,command,arg_count,parms_info,use_hmac):
    self.command = command.upper()
    self.arg_count = int(arg_count)
    self.parms_info = parms_info
    self.use_hmac = bool(use_hmac)
    MessageStrategy.strategies[self.command] = self

  def build(self,args,hmacf=None):
    assert len(args)==self.arg_count
    if self.use_hmac:
      assert hmacf
    else:
      hmacf = lambda x: ""
    msg = ("{} ".format(self.command) + " ".join(*args)).strip()
    msg += " " + hmacf(msg)
    msg = msg.strip() + "\n"
    log(msg)
    if len(msg) < _min_msg_size:
      msg += (512-len(msg)) * "_"
    return msg

  def parse(self,msg,hmacf=None):
    msg = msg.strip().split()
    assert msg[0]==self.command
    if self.use_hmac:
      assert hmacf
      if self.arg_count+2 != len(msg):
        raise BadMessageError("Bad Message Format")
      hmac = msg[-1]
      if hmac != hmacf(msg[:-1]):
        raise BadMessageError("HMAC Failure")
    else:
      if self.arg_count+1 != len(msg):
        raise BadMessageError("Bad Message Format")
    msg_args = dict()
    if self.parms_info:
      for i in range(self.arg_count):
        msg_args[self.parms_info[i]] = msg[i+1]
    return msg_args

  def __repr__(self):
    str(self.__class__) + ": " + str(self.__dict__)


HelloServerStrategy		= MessageStrategy("HELLO_SERVER",1,["Version"],False)
HelloClientStrategy		= MessageStrategy("HELLO_CLIENT",1,["Version"],False)
DieStrategy			= MessageStrategy("DIE",0,None,False)
PullFileStrategy		= MessageStrategy("PULL_FILE",1,["File Name"],True)
PushFileStrategy		= MessageStrategy("PUSH_FILE",2,["File Name","Data","CurPart","EndPart"],True)
ErrorServerStrategy		= MessageStrategy("ERROR_SERVER",1,["Error Message"],True)
AuthSubjectStrategy		= MessageStrategy("AUTH_SUBJECT",3,["Subject","Key","Salt"],False)
ListSubjectsClientStrategy	= MessageStrategy("LIST_SUBJECT_CLIENT",1,None,True)
ListSubjectsServerStrategy	= MessageStrategy("LIST_SUBJECT_SERVER",1,["Subjects"],True)
ListObjectsClientStrategy	= MessageStrategy("LIST_OBJECT_CLIENT",1,None,True)
ListObjectsServerStrategy	= MessageStrategy("LIST_OBJECT_SERVER",1,["Objects"],True)
GiveTicketSubject		= MessageStrategy("GIVE_TICKET_SUBJECT",1,["Ticket"],True)
TakeTicketSubject		= MessageStrategy("TAKE_TICKET_SUBJECT",1,["Ticket"],True)
MakeDirectory			= MessageStrategy("MAKE_DIRECTORY",1,["Directory"],True)
MakeSubject			= MessageStrategy("MAKE_SUBJECT",1,["Subject"],True)
ChangeDirStrategy		= MessageStrategy("CD",1,["Local Path Name"],True)
MakeFilter			= MessageStrategy("MAKE_FILTER",1,["Subject1","Subject2","Ticket"],True)
MakeLink			= MessageStrategy("MAKE_LINK",1,["Subject1","Subject2"],True)
DeleteFileStrategy		= MessageStrategy("DELETE_FILE",1,["File Name"],True)
ClearFilters			= MessageStrategy("CLEAR_FILTERS",1,["Subject"],True)
ClearLinks			= MessageStrategy("CLEAR_LINKS",1,["Subject"],True)

strategies = MessageStrategy.strategies

#Notes
#
#Only subjects can have tickets (to objects)
#Must have access tickets to directory to list directory contents
#Objects are implicitly linked to all subjects that can view the directory
#Links between subjects are explicit and must exist for any transfer of tickets to occur
#Built messages are padded at the end with spaces, leading and trailing spaces must be ignored
#  by the client and the server. This hides the length of control messages
#Passwords are stored on the server for each client as the shared secret for key generation
#Direction of links and filters does matter
#Super subjects exist that can create and destroy links and filters
