from . import __version__, _msg_size, _hash_rounds
from SPM.Util import log

from time import time as time_sec
from time import sleep
import os
import inspect
import socket
import hashlib

from SPM.Messages import MessageStrategy, MessageClass, MessageType
from SPM.Messages import BadMessageError
from SPM.Database import Database
from SPM.Database import DatabaseError
from SPM.Tickets import Ticket, BadTicketError
from SPM.Stream import RC4, make_hmacf

strategies = MessageStrategy.strategies
db = Database()

#Events and shared event data

class ClientData:
  
  def __init__(self,socket):
    self.socket = socket          #Client communication socket
    self.msg_dict = None          #Client msg about to be dispatched
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
    self.data = None              #Binary file data block
    self.curpart = 0              #Xfer progress
    self.endpart = 0              #Xfer EOF detection
    self.cd = "/"                 #Client virtual working directory
    
  def useMsg(self):
    assert self.msg_dict
    msg_dict = self.msg_dict
    self.msg_dict = None
    return msg_dict

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

def scan_for_message_and_parse(scope):
  if scope.msg_dict:
    raise RuntimeError("BUG! Never scan for msg before disposal of previous")
  if len(scope.buf) >= _msg_size:
    scope.msg_dict = MessageStrategy.parse(scope.buf[0:_msg_size],stream=scope.stream,hmacf=scope.hmacf)
    scope.buf = scope.buf[_msg_size:]

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
      try:
        scan_for_message_and_parse(scope)
      except BadMessageError:
        dq.append(lambda: Events.replyErrorMessage(dq,"BadMessageError",scope,
                                                 lambda: Events.die(dq,scope)))
        return
    if scope.msg_dict:
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
    dq.append(lambda: next())

  @staticmethod
  def checkHelloAndReply(dq,scope):
    log_this_func()
    assert(scope.msg_dict)
    msg_dict = scope.useMsg()
    if not msg_dict["MessageType"] == MessageType.HELLO_CLIENT:
      dq.append(lambda: Events.replyErrorMessage(dq,"Expected client greeting.",scope,
                                                 lambda: Events.die(dq,scope)))
      return
    log("Client reported version: %s" % msg_dict["Version"])
    if __version__ != msg_dict["Version"]:
      dq.append(lambda: Events.replyErrorMessage(dq,"Version mismatch.",scope,
                                                 lambda: Events.die(dq,scope)))
      return
    scope.socket.sendall(strategies[(MessageClass.PUBLIC_MSG,MessageType.HELLO_SERVER)].build([__version__]))
    dq.append(lambda: Events.waitForNextMessage(dq,scope))

  @staticmethod
  def waitForNextMessage(dq,scope):
    log_this_func()
    if scope.msg_dict:
      raise RuntimeError("BUG! Cannot wait for msg while msg pending")
    while len(scope.buf) >= _msg_size:
      try:
        scan_for_message_and_parse(scope)
      except BadMessageError:
        dq.append(lambda: Events.replyErrorMessage(dq,"BadMessageError",scope,
                                                 lambda: Events.die(dq,scope)))
        return
      msg_dict = scope.useMsg()
      msg_type = msg_dict["MessageType"]
      #Switch on all possible messages
      if msg_type == MessageType.DIE:
        dq.append(lambda: Events.die(dq,scope))
        return #No parallel dispatch
      elif msg_type == MessageType.PULL_FILE:
        scope.filename = msg_dict["File Name"]
        scope.curpart = 0
        scope.endpart = 0
        dq.append(lambda: Events.pushFile(dq,scope))
        return #No parallel dispatch
      elif msg_type == MessageType.PUSH_FILE:
        scope.filename = msg_dict["File Name"]
        scope.data = msg_dict["Data"]
        scope.curpart = 0
        scope.endpart = msg_dict["EndPart"]
        dq.append(lambda: Events.pullFile(dq,scope))
        return #No parallel dispatch
      elif msg_type == MessageType.AUTH_SUBJECT:
        scope.target = msg_dict["Subject"]
        scope.salt = msg_dict["Salt"]
        dq.append(lambda: Events.authenticate(dq,scope))
        return
      elif msg_type == MessageType.LIST_SUBJECT_CLIENT:
        dq.append(lambda: Events.listSubjects(dq,scope))
      elif msg_type == MessageType.LIST_OBJECT_CLIENT:
        dq.append(lambda: Events.listObjects(dq,scope))
      elif msg_type == MessageType.GIVE_TICKET_SUBJECT:
        scope.target = msg_dict["Subject"]
        try:
          scope.ticket = Ticket(msg_dict["Ticket"])
        except BadTicketError:
          dq.append(lambda: Events.replyErrorMessage(dq,"BadTicketError",scope,
                                                     lambda: Events.die(dq,scope)))
          return
        dq.append(lambda: Events.giveTicket(dq,scope))
      elif msg_type == MessageType.TAKE_TICKET_SUBJECT:
        scope.target = msg_dict["Subject"]
        try:
          scope.ticket = Ticket(msg_dict["Ticket"])
        except BadTicketError:
          dq.append(lambda: Events.replyErrorMessage(dq,"BadTicketError",scope,
                                                     lambda: Events.die(dq,scope)))
          return
        dq.append(lambda: Events.takeTicket(dq,scope))
      elif msg_type == MessageType.MAKE_DIRECTORY:
        scope.target = msg_dict["Directory"]
        dq.append(lambda: Events.makeDirectory(dq.scope))
      elif msg_type == MessageType.MAKE_SUBJECT:
        scope.target = msg_dict["Subject"]
        scope.t_password = msg_dict["Password"]
        dq.append(lambda: Events.makeSubject(dq,scope))
      elif msg_type == MessageType.CD:
        scope.target = msg_dict["Path"]
        dq.append(lambda: Events.changeDirectory(dq,scope))
      elif msg_type == MessageType.MAKE_FILTER:
        scope.subject1 = msg_dict["Subject1"]
        scope.subject2 = msg_dict["Subject2"]
        try:
          scope.ticket = Ticket(msg_dict["Ticket"])
        except BadTicketError:
          dq.append(lambda: Events.replyErrorMessage(dq,"BadTicketError",scope,
                                                     lambda: Events.die(dq,scope)))
          return
        dq.append(lambda: Events.makeFilter(dq,scope))
      elif msg_type == MessageType.MAKE_LINK:
        scope.subject1 = msg_dict["Subject1"]
        scope.subject2 = msg_dict["Subject2"]
        dq.append(lambda: Events.makeLink(dq,scope))
      elif msg_type == MessageType.DELETE_FILE:
        scope.filename = msg_dict["File Name"]
        dq.append(lambda: Events.deleteFile(dq,scope))
      elif msg_type == MessageType.CLEAR_FILTERS:
        scope.target = msg_dict["Subject"]
        dq.append(lambda: Events.clearFilters(dq,scope))
      elif msg_type == MessageType.CLEAR_LINKS:
        scope.target = msg_dict["Subject"]
        dq.append(lambda: Events.clearLinks(dq,scope))
      elif msg_type == MessageType.DELETE_SUBJECT:
        scope.target = msg_dict["Subject"]
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
    except DatabaseError as e:
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
      except DatabaseError as e:
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
    try:
      scope.fd.write(scope.data)
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
    msg_dict = scope.useMsg()
    if msg_dict["MessageType"] != MessageType.PUSH_FILE:
      dq.append(lambda: Events.replyErrorMessage(dq,"Bad message sequence",scope,
                                                     lambda: Events.die(dq,scope)))
    else:
      next_filename = msg_dict["File Name"]
      scope.data = msg_dict["Data"]
      next_curpart = msg_dict["CurPart"]
      next_endpart = msg_dict["EndPart"]
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
        data = scope.fd.read(sendsize)
      except IOError:
        dq.append(lambda: Events.replyErrorMessage(dq,"Error reading file",scope,
                                                     lambda: Events.die(dq,scope)))
        return
      msg_encoded = strategies[(MessageClass.PRIVATE_MSG,MessageType.PUSH_FILE)].build([
        scope.filename,data,scope.curpart,scope.endpart],scope.stream,scope.hmacf)
      scope.curpart += 1
      scope.socket.sendall(msg_encoded)
      dq.append(lambda: Events.sendFilePart(dq,scope))

  @staticmethod
  def authenticate(dq,scope):
    assert(scope.target)
    assert(scope.salt)
    try:
      target_entry = db.getSubject(scope.target)
      if target_entry:
        scope.key = hashlib.pbkdf2_hmac(target_entry.subject,target_entry.password,scope.salt,
                                  _hash_rounds, dklen=256)
        scope.stream = RC4(scope.key)
        scope.hmacf = make_hmacf(scope.key)
        msg_encoded = strategies[(MessageClass.PRIVATE_MSG,MessageType.CONFIRM_AUTH)].build([
          target_entry.subject],scope.stream,scope.hmacf)
        scope.subject = target_entry.subject
      else:
        msg_encoded = strategies[(MessageClass.PUBLIC_MSG,MessageType.REJECT_AUTH)].build()
        scope.key = None
        scope.stream = None
        scope.hmacf = None
      scope.socket.sendall(msg_encoded)
      dq.append(lambda: Events.waitForNextMessage(dq,scope))
    except DatabaseError as e:
      dq.append(lambda: Events.replyErrorMessage(dq,str(e),scope,
                                                     lambda: Events.die(dq,scope)))
    except BadMessageError:
      dq.append(lambda: Events.replyErrorMessage(dq,"BadMessageError",scope,
                                                     lambda: Events.die(dq,scope)))
      
  @staticmethod
  def replyErrorMessage(dq,message,scope,next):
    log_this_func()
    log("Sent error message: %s" % message)
    if scope.stream:
      msg_encoded = strategies[(MessageClass.PRIVATE_MSG,MessageType.ERROR_SERVER)].build(message)
    else:
      msg_encoded = strategies[(MessageClass.PUBLIC_MSG,MessageType.ERROR_SERVER)].build(message)
    scope.socket.sendall(msg_encoded)
    dq.append(lambda: next())

  @staticmethod
  def die(dq,scope):
    log_this_func()
    if scope.stream:
      msg_encoded = strategies[(MessageClass.PRIVATE_MSG,MessageType.DIE)].build()
    else:
      msg_encoded = strategies[(MessageClass.PUBLIC_MSG,MessageType.DIE)].build()
    scope.socket.sendall(msg_encoded)
    scope.socket.close()

