from . import __version__, _max_msg_size, _hash_rounds
from SPM.Util import log

from time import time as time_sec
from time import sleep
import inspect
import socket
import base64
import hashlib

from SPM.Messages import MessageStrategy
from SPM.Messages import BadMessageError
from SPM.Database import Database
from SPM.Database import DatabaseError
from SPM.Ticket import Ticket
from SPM.Stream import RC4, make_hmac

strategies = MessageStrategy.strategies
db = Database()

#Events and shared event data

class ClientData:
  
  def __init__(self,socket):
    self.socket = socket          #Client communication socket
    self.msg = None               #Client msg about to be dispatched
    self.buf = bytearray()        #Recv buffer for client messages
    self.subject = None           #Authenticated subject under which client acts
    self.subject1 = None          #Multi-subject
    self.subject2 = None          #Multi-subject
    self.target = None            #Single subject argument
    self.t_password = None        #Target subject's password
    self.ticket = None            #Ticket
    self.salt = None              #Salt
    self.key = None               #Encryption key
    self.hmacf = None             #Message signing function
    self.stream = None            #Keystream generator object
    self.lastreadtime = None      #Last attempt to read from socket
    self.blocktime = 0            #Time to sleep after reading empty socket
    self.filename = None          #File name
    self.fd = None
    self.data = None              #Base64-encoded file data block
    self.curpart = 0              #Xfer progress
    self.endpart = 0              #Xfer EOF detection
    self.cd = "/"                 #Client virtual working directory
    
  def useMsg(self):
    assert self.msg
    msg = self.msg
    self.msg = None
    return msg

#Utility functions (for code readability), time units are in ms
log_this_func = lambda: log(inspect.stack()[1][3])
time = lambda: time_sec()*1000

#Set first lastreadtime to a resonable value
def init_lastreadtime(scope):
  if scope.lastreadtime is None:
    scope.lastreadtime = time()

#Measure time we last tried to read from the socket and block if no data to keep the time
#  for an event to pass through the queue near target_depth ms. If the server starts
#  getting busy, we quickly back off. Ultimately the server becomes non-blocking when
#  the queue is busy. When idle, the server slowly increments the socket block time until
#  the queue is once again target_depth ms long, spending most of its time blocked on
#  the socket, waiting for data
#
#This is done to avoid spinning on the non-blocking socket when there is nothing to do but
#  check for incoming data (in this case we will soon block a long time), while not blocking
#  when the server is fully loaded (in this case we quickly handle the check socket event
#  to move on with more pressing matters...)
def update_blocktime(scope):
  init_lastreadtime(scope)
  ct = time()
  scope.blocktime = next_block_time(scope.blocktime,ct-scope.lastreadtime)
  scope.lastreadtime = ct

def next_block_time(last_time,call_delta,target_depth=700,precision=10):
  if call_delta > target_depth:
    return last_time//2
  return last_time+precision

def scan_for_message_and_divide_if_finished(scope):
  if scope.msg:
    raise RuntimeError("BUG! Never scan for msg before disposal of previous")
  if b"\n" in scope.buf:
    split_buf = scope.buf.split(b"\n")
    if scope.stream:
      split_buf[0] = scope.stream.decrypt(split_buf[0])
    scope.msg = split_buf[0].strip().decode(encoding="UTF-8",errors="ignore")
    scope.buf = b''.join(split_buf[1:])


class Events:

  @staticmethod
  def acceptClient(dq,socket):
    log_this_func()
    addr = socket.getpeername()
    print("Accepted connection from %s:%i" % addr)
    scope = ClientData(socket)
    dq.append(lambda: Events.readUntilMessageEnd(dq,scope,
	lambda: Events.checkHelloAndReply(dq,scope)))

  @staticmethod
  def readUntilMessageEnd(dq,scope,next):
    if scope.buf:
      scan_for_message_and_divide_if_finished(scope)
    if scope.msg:
      log("Got full message")
      dq.append(lambda: next())
    else:
      dq.append(lambda: Events.readMessagePart(dq,scope,
	lambda: Events.readUntilMessageEnd(dq,scope,next)))

  @staticmethod
  def readMessagePart(dq,scope,next):
    update_blocktime(scope)
    try:
      incoming_part = bytearray(scope.socket.recv(4096))
      scope.buf.extend(incoming_part)
      sleep(scope.blocktime/1000)
    except socket.timeout:
      pass
    if len(scope.buf) > _max_msg_size:
      dq.append(lambda: Events.replyErrorMessage(dq,"Message too large.",scope,
                                                 lambda: Events.die(dq,scope)))
    else:
      dq.append(lambda: next())

  @staticmethod
  def checkHelloAndReply(dq,scope):
    log_this_func()
    assert(scope.msg)
    msg = scope.useMsg().split()
    if not msg[0]=="HELLO_CLIENT":
      dq.append(lambda: Events.replyErrorMessage(dq,"Unexpected message type.",scope,
                                                 lambda: Events.die(dq,scope)))
      return
    args_dict = strategies[msg[0]].parse(msg)
    log("Client reported version: %s" % args_dict["Version"])
    if str(__version__) != args_dict["Version"]:
      dq.append(lambda: Events.replyErrorMessage(dq,"Version mismatch.",scope,
                                                 lambda: Events.die(dq,scope)))
      return
    scope.socket.sendall(strategies["HELLO_SERVER"].build([__version__]))
    dq.append(lambda: Events.waitForNextMessage(dq,scope))

  @staticmethod
  def waitForNextMessage(dq,scope):
    log_this_func()
    if scope.msg:
      raise RuntimeError("BUG! Cannot wait for msg while msg pending")
    while b"\n" in scope.buf:
      scan_for_message_and_divide_if_finished(scope)
      #Switch on all possible messages
      msg = scope.useMsg().split()
      msg_type = msg[0]
      try:
        args_dict = strategies[msg_type].parse(msg,scope.hmacf)
      except KeyError:
        dq.append(lambda: Events.replyErrorMessage(dq,"Unknown message type.",scope,
                                                 lambda: Events.die(dq,scope)))
        return
      except BadMessageError, e:
        dq.append(lambda: Events.replyErrorMessage(dq,str(e),scope,
                                                 lambda: Events.die(dq,scope)))
        return
      if msg_type == "DIE":
        dq.append(lambda: Events.die(dq,scope))
        return #No parallel dispatch
      elif msg_type == "PULL_FILE":
        scope.filename = args_dict["File Name"]
        scope.curpart = 0
        scope.endpart = 0
        dq.append(lambda: Events.pushFile(dq,scope))
        return #No parallel dispatch
      elif msg_type == "PUSH_FILE":
        scope.filename = args_dict["File Name"]
        scope.data = args_dict["Data"]
        scope.curpart = args_dict["CurPart"]
        scope.endpart = args_dict["EndPart"]
        dq.append(lambda: Events.pullFile(dq,scope))
        return #No parallel dispatch
      elif msg_type == "AUTH_SUBJECT":
        scope.target = args_dict["Subject"]
        scope.salt = args_dict["Salt"]
        dq.append(lambda: Events.authenticate(dq,scope))
        return
      elif msg_type == "LIST_SUBJECT_CLIENT":
        dq.append(lambda: Events.listSubjects(dq,scope))
      elif msg_type == "LIST_OBJECT_CLIENT":
        dq.append(lambda: Events.listObjects(dq,scope))
      elif msg_type == "GIVE_TICKET_SUBJECT":
        scope.target = args_dict["Subject"]
        try:
          scope.ticket = Ticket(args_dict["Ticket"])
        except BadTicketError, e:
          dq.append(lambda: Events.replyErrorMessage(dq,str(e),scope,
                                                     lambda: Events.die(dq,scope)))
          return
        dq.append(lambda: Events.giveTicket(dq,scope))
      elif msg_type == "TAKE_TICKET_SUBJECT":
        scope.target = args_dict["Subject"]
        try:
          scope.ticket = Ticket(args_dict["Ticket"])
        except BadTicketError, e:
          dq.append(lambda: Events.replyErrorMessage(dq,str(e),scope,
                                                     lambda: Events.die(dq,scope)))
          return
        dq.append(lambda: Events.takeTicket(dq,scope))
      elif msg_type == "MAKE_DIRECTORY":
        scope.target = args_dict["Directory"]
        dq.append(lambda: Events.makeDirectory(dq.scope))
      elif msg_type == "MAKE_SUBJECT":
        scope.target = args_dict["Subject"]
        scope.t_password = args_dict["Password"]
        dq.append(lambda: Events.makeSubject(dq,scope))
      elif msg_type == "CD":
        scope.target = args_dict["Path"]
        dq.append(lambda: Events.changeDirectory(dq,scope))
      elif msg_type == "MAKE_FILTER":
        scope.subject1 = args_dict["Subject1"]
        scope.subject2 = args_dict["Subject2"]
        try:
          scope.ticket = Ticket(args_dict["Ticket"])
        except BadTicketError, e:
          dq.append(lambda: Events.replyErrorMessage(dq,str(e),scope,
                                                     lambda: Events.die(dq,scope)))
          return
        dq.append(lambda: Events.makeFilter(dq,scope))
      elif msg_type == "MAKE_LINK":
        scope.subject1 = args_dict["Subject1"]
        scope.subject2 = args_dict["Subject2"]
        dq.append(lambda: Events.makeLink(dq,scope))
      elif msg_type == "DELETE_FILE":
        scope.filename = args_dict["File Name"]
        dq.append(lambda: Events.deleteFile(dq,scope))
      elif msg_type == "CLEAR_FILTERS":
        scope.target = args_dict["Subject"]
        dq.append(lambda: Events.clearFilters(dq,scope))
      elif msg_type == "CLEAR_LINKS"
        scope.target = args_dict["Subject"]
        dq.append(lambda: Events.clearLinks(dq,scope))
      elif msg_type == "DELETE_SUBJECT":
        scope.target = args_dict["Subject"]
        dq.append(lambda: Events.deleteSubject(dq,scope))
    dq.append(lambda: Events.readUntilMessageEnd(dq,scope,
	lambda: Events.waitForNextMessage(dq,scope)))

  @staticmethod
  def pushFile(dq,scope):
    log_this_func()
    assert scope.filename
    assert scope.curpart == 0
    assert scope.endpart == 0
    assert scope.stream
    localpath = os.path.join(scope.cd,scope.filename)
    try:
      if not db.getObject(localpath):
        dq.append(lambda: Events.replyErrorMessage(dq,"Object does not exist in database",scope,
                                                 lambda: Events.die(dq,scope)))
        return
      scope.fd = db.readObject(localpath)
    except DatabaseError, e:
      dq.append(lambda: Events.replyErrorMessage(dq,str(e),scope,
                                                     lambda: Events.die(dq,scope)))
      return
    except IOError:
      dq.append(lambda: Events.replyErrorMessage(dq,"Error reading file",scope,
                                                 lambda: Events.die(dq,scope)))
      return
    log("Opened '{}' for reading".format(localpath))
    dq.append(lambda: Events.sendFilePart(dq,scope))

  @staticmethod
  def pullFile(dq,scope):
    log_this_func()
    assert scope.filename
    assert scope.data
    assert scope.curpart
    assert scope.endpart
    assert scope.stream
    if scope.curpart != 0:
      dq.append(lambda: Events.replyErrorMessage(dq,"Push must start at zero.",scope,
                                                 lambda: Events.die(dq,scope)))
    elif scope.endpart <= 0:
      dq.append(lambda: Events.replyErrorMessage(dq,"File must have a block.",scope,
                                                 lambda: Events.die(dq,scope)))
    else:
      localpath = os.path.join(scope.cd,scope.filename)
      try:
        if db.getObject(localpath):
          dq.append(lambda: Events.replyErrorMessage(dq,"Object already exists in database",scope,
                                                 lambda: Events.die(dq,scope)))
          return
        db.insertObject(localpath)
        scope.fd = db.writeObject(localpath)
      except DatabaseError, e:
        dq.append(lambda: Events.replyErrorMessage(dq,str(e),scope,
                                                     lambda: Events.die(dq,scope)))
        return
      except IOError:
        dq.append(lambda: Events.replyErrorMessage(dq,"Error writing file",scope,
                                                     lambda: Events.die(dq,scope)))
        return
      log("Opened '{}' for writing after object insertion".format(localpath))
      dq.append(lambda: Events.pullFilePart(dq,scope))

  @staticmethod
  def pullFilePart(dq,scope):
    log_this_func()
    assert scope.filename
    assert scope.fd
    assert scope.stream
    assert scope.curpart
    assert scope.endpart
    assert scope.data
    bin_data = base64.b64decode(data)
    try:
      scope.fd.write(bin_data)
    except IOError:
      dq.append(lambda: Events.replyErrorMessage(dq,"Error writing file",scope,
                                                     lambda: Events.die(dq,scope)))
      return
    if scope.curpart == scope.endpart:
      scope.curpart = 0
      scope.endpart = 0
      scope.filename = None
      scope.fd.close()
      scope.fd = None
      scope.data = None
      log("All file parts have been recorded.")
      dq.append(lambda: Events.waitForNextMessage(dq,scope))
    else:
      scope.curpart += 1
      dq.append(lambda: Events.readUntilMessageEnd(dq, scope,
                    lambda: Events.unpackMsgToPullFilePart(dq,scope)))

  @staticmethod
  def unpackMsgToPullFilePart(dq,scope):
    full_msg = scope.useMsg()
    msg_type = msg.split()[0]
    if msg_type != "PUSH_FILE":
      dq.append(lambda: Events.replyErrorMessage(dq,"Unexpected message type",scope,
                                                     lambda: Events.die(dq,scope)))
    else:
      try:
        args_dict = strategies["PUSH_FILE"].parse(full_msg,scope.hmacf)
      except BadMessageError, e:
        dq.append(lambda: Events.replyErrorMessage(dq,str(e),scope,
                                                     lambda: Events.die(dq,scope)))
        return
      next_filename = args_dict["File Name"]
      scope.data = args_dict["Data"]
      next_curpart = args_dict["CurPart"]
      next_endpart = args_dict["EndPart"]
      if (next_filename != scope.filename or next_curpart != scope.curpart or
          next_endpart != scope.endpart):
        dq.append(lambda: Events.replyErrorMessage(dq,"Bad message sequence",scope,
                                                     lambda: Events.die(dq,scope)))
        return
      dq.append(lambda: Events.pullFilePart(dq,scope))

  @staticmethod
  def sendFilePart(dq,scope,sendsize=800):
    log_this_func()
    assert scope.filename
    assert scope.fd
    assert scope.stream
    if scope.curpart > scope.endpart:
      scope.curpart = 0
      scope.endpart = 0
      scope.filename = None
      scope.fd.close()
      scope.fd = None
      scope.data = None
      log("All file parts have been sent.")
      dq.append(lambda: Events.waitForNextMessage(dq,scope))
    else:
      try:
        data = base64.b64encode(fd.read(sendsize)).decode(encoding='UTF-8',errors='strict')
      except IOError:
        dq.append(lambda: Events.replyErrorMessage(dq,"Error reading file",scope,
                                                     lambda: Events.die(dq,scope)))
        return
      msg_encoded = scope.stream.encrypt(strategies["PUSH_FILE"].build([
        scope.filename,data,scope.curpart,scope.endpart],scope.hmacf))
      scope.curpart += 1
      scope.socket.sendall(msg_encoded)
      dq.append(lambda: Events.sendFilePart(dq,scope))

  @staticmethod
  def authenticate(dq,scope):
    assert(scope.target)
    assert(scope.salt)
    try:
      target_entry = db.getSubject(scope,target)
      if target_entry:
        scope.key = hashlib.pbkdf2_hmac(target_entry.subject,target_entry.password,scope.salt,
                                  _hash_rounds, dklen=256)
        scope.stream = RC4(scope.key)
        scope.hmacf = make_hmac(scope.key)
        msg_encoded = scope.stream.encrypt(strategies["CONFIRM_AUTH"].build([
          target_entry.subject],scope.hmacf))
        scope.socket.sendall(msg_encoded)
        dq.append(lambda: Events.waitForNextMessage(dq,scope))
      else:
        dq.append(lambda: Events.replyErrorMessage(dq,"Authentication failure",scope,
                                                     lambda: Events.die(dq,scope)))
    except DatabaseError, BadMessageError, e:
      dq.append(lambda: Events.replyErrorMessage(dq,str(e),scope,
                                                     lambda: Events.die(dq,scope)))

  @staticmethod
  def replyErrorMessage(dq,message,scope,next):
    log_this_func()
    log("Sent error message: %s" % message)
    scope.socket.sendall(message.encode(encoding="UTF-8"),errors='strict')
    dq.append(lambda: next())

  @staticmethod
  def die(dq,scope):
    log_this_func()
    outgoing = strategies["DIE"].build()
    if scope.stream:
      outgoing = scope.stream.encrypt(outgoing)
    scope.socket.sendall(outgoing)
    scope.socket.close()

