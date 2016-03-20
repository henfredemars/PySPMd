from . import __version__, _msg_size, _hash_rounds, _data_size
from SPM.Util import log

from time import sleep
import os
import inspect
import socket
import hashlib

from SPM.Messages import MessageStrategy, MessageClass, MessageType
from SPM.Messages import BadMessageError
from SPM.Database import DatabaseError
from SPM.Tickets import Ticket, BadTicketError
from SPM.Stream import RC4, make_hmacf
from SPM.Priority import Priority

strategies = MessageStrategy.strategies
db = None #Worker thread must initialize this to Database() because
          #sqlite3 demands same thread uses this reference

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
    self.priority = 0             #Time left to sleep-500ms
    self.filename = None          #File name
    self.fd = None                #Open file discriptor
    self.in_data = None           #Incoming data block
    self.out_data = None          #Outgoing data block
    self.bytes_sent = 0           #Bytes sent of message to client
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

def scan_for_message_and_parse(scope):
  if scope.msg_dict:
    raise RuntimeError("BUG! Never scan for msg before disposal of previous")
  if len(scope.buf) >= _msg_size:
    scope.msg_dict = MessageStrategy.parse(scope.buf[0:_msg_size],stream=scope.stream,hmacf=scope.hmacf)
    scope.buf = scope.buf[_msg_size:]

class Events:

  @staticmethod
  def acceptClient(i,pq,socket):
    log_this_func()
    socket.setblocking(False)
    addr = socket.getpeername()
    print("Accepted connection from %s:%i" % addr)
    scope = ClientData(socket)
    pq.put(Priority.HIGH.value,lambda i: Events.readUntilMessageEnd(i,pq,scope,
	lambda j: Events.checkHelloAndReply(j,pq,scope)))

  @staticmethod
  def readUntilMessageEnd(i,pq,scope,next):
    log_this_func()
    if scope.buf:
      try:
        scan_for_message_and_parse(scope)
      except BadMessageError:
        pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"BadMessageError",scope,
                                                 lambda j: Events.die(j,pq,scope)))
        return
    if scope.msg_dict:
      log("Got full message")
      pq.put(Priority.HIGH.value,lambda i: next(i))
    else:
      pq.put(i,lambda i: Events.readMessagePart(i,pq,scope,
	lambda j: Events.readUntilMessageEnd(j,pq,scope,next)))

  @staticmethod
  def readMessagePart(i,pq,scope,next):
    log_this_func()
    assert socket
    try:
      incoming_part = bytearray(scope.socket.recv(4096))
      scope.buf.extend(incoming_part)
    except socket.timeout:
      pass
    if incoming_part:
      pq.put(Priority.HIGH.value,lambda i: next(i))
    else:
      pq.put(i+Priority.PRECISION.value,lambda i: next(i))

  @staticmethod
  def sendMessage(i,pq,scope,next):
    log_this_func()
    assert(scope.socket)
    assert(scope.out_data)
    scope.bytes_sent = 0
    Events.sendMessagePart(i,pq,scope,next)

  @staticmethod
  def sendMessagePart(i,pq,scope,next):
    log_this_func()
    scope.bytes_sent += scope.socket.send(scope.out_data)
    if scope.bytes_sent == 0:
      pq.put(i+Priority.PRECISION.value,lambda i: Events.sendMessagePart(i,pq,scope,next))
    elif scope.bytes_sent != len(scope.out_data):
      pq.put(i,lambda i: Events.sendMessagePart(i,pq,scope,next))
    else:
      scope.bytes_sent = 0
      scope.out_data = None
      pq.put(Priority.HIGH.value,lambda i: next(i))
      
  @staticmethod
  def checkHelloAndReply(i,pq,scope):
    log_this_func()
    assert(scope.msg_dict)
    msg_dict = scope.useMsg()
    if not msg_dict["MessageType"] == MessageType.HELLO_CLIENT:
      pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"Expected client greeting.",scope,
                                                   lambda j: Events.die(j,pq,scope)))
      return
    log("Client reported version: %s" % msg_dict["Version"])
    if __version__ != msg_dict["Version"]:
      pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"Version mismatch.",scope,
                                                   lambda j: Events.die(j,pq,scope)))
      return
    scope.out_data = strategies[(MessageClass.PUBLIC_MSG,MessageType.HELLO_SERVER)].build([__version__])
    Events.sendMessage(i,pq,scope, lambda i: Events.waitForNextMessage(i,pq,scope))

  @staticmethod
  def waitForNextMessage(i,pq,scope):
    while len(scope.buf) >= _msg_size or scope.msg_dict:
      try:
        if not scope.msg_dict:
          scan_for_message_and_parse(scope)
      except BadMessageError:
        pq.put(Priority.HIGH,value,lambda i: Events.replyErrorMessage(i,pq,"BadMessageError",scope,
                                                   lambda j: Events.die(j,pq,scope)))
        return
      msg_dict = scope.useMsg()
      msg_type = msg_dict["MessageType"]
      log(str(msg_type))
      #Switch on all possible messages
      if msg_type == MessageType.DIE:
        scope.socket.close()
        return #No parallel dispatch
      elif msg_type == MessageType.PULL_FILE:
        scope.filename = msg_dict["File Name"]
        scope.curpart = 0
        scope.endpart = 0
        pq.put(Priority.HIGH.value,lambda i: Events.pushFile(i,pq,scope))
        return #No parallel dispatch
      elif msg_type == MessageType.PUSH_FILE:
        scope.filename = msg_dict["File Name"]
        scope.in_data = None
        scope.curpart = 0
        scope.endpart = msg_dict["EndPart"]
        pq.put(Priority.HIGH.value,lambda i: Events.pullFile(i,pq,scope))
        return #No parallel dispatch
      elif msg_type == MessageType.AUTH_SUBJECT:
        scope.target = msg_dict["Subject"]
        scope.salt = msg_dict["Salt"]
        pq.put(Priority.HIGH.value,lambda i: Events.authenticate(i,pq,scope))
        return
      elif msg_type == MessageType.LIST_SUBJECT_CLIENT:
        pq.put(Priority.HIGH.value,lambda i: Events.listSubjects(i,pq,scope))
      elif msg_type == MessageType.LIST_OBJECT_CLIENT:
        pq.put(Priority.HIGH.value,lambda i: Events.listObjects(i,pq,scope))
      elif msg_type == MessageType.GIVE_TICKET_SUBJECT:
        scope.target = msg_dict["Subject"]
        try:
          scope.ticket = Ticket(msg_dict["Ticket"])
        except BadTicketError:
          pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"BadTicketError",scope,
                                                     lambda j: Events.die(j,pq,scope)))
          return
        pq.put(Priority.HIGH.value,lambda i: Events.giveTicket(i,pq,scope))
      elif msg_type == MessageType.TAKE_TICKET_SUBJECT:
        scope.target = msg_dict["Subject"]
        try:
          scope.ticket = Ticket(msg_dict["Ticket"])
        except BadTicketError:
          pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"BadTicketError",scope,
                                                     lambda j: Events.die(j,pq,scope)))
          return
        pq.put(Priority.HIGH.value,lambda i: Events.takeTicket(i,pq,scope))
      elif msg_type == MessageType.MAKE_DIRECTORY:
        scope.target = msg_dict["Directory"]
        pq.put(Priority.HIGH.value,lambda i: Events.makeDirectory(i,pq.scope))
      elif msg_type == MessageType.MAKE_SUBJECT:
        scope.target = msg_dict["Subject"]
        scope.t_password = msg_dict["Password"]
        pq.put(Priority.HIGH.value,lambda i: Events.makeSubject(i,pq,scope))
      elif msg_type == MessageType.CD:
        scope.target = msg_dict["Path"]
        pq.put(Priority.HIGH.value,lambda i: Events.changeDirectory(i,pq,scope))
      elif msg_type == MessageType.MAKE_FILTER:
        scope.subject1 = msg_dict["Subject1"]
        scope.subject2 = msg_dict["Subject2"]
        try:
          scope.ticket = Ticket(msg_dict["Ticket"])
        except BadTicketError:
          pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"BadTicketError",scope,
                                                     lambda j: Events.die(j,pq,scope)))
          return
        pq.put(Priority.HIGH.value,lambda i: Events.makeFilter(i,pq,scope))
      elif msg_type == MessageType.MAKE_LINK:
        scope.subject1 = msg_dict["Subject1"]
        scope.subject2 = msg_dict["Subject2"]
        pq.put(Priority.HIGH.value,lambda i: Events.makeLink(i,pq,scope))
      elif msg_type == MessageType.DELETE_FILE:
        scope.filename = msg_dict["File Name"]
        pq.put(Priority.HIGH.value,lambda i: Events.deleteFile(i,pq,scope))
      elif msg_type == MessageType.CLEAR_FILTERS:
        scope.target = msg_dict["Subject"]
        pq.put(Priority.HIGH.value,lambda i: Events.clearFilters(i,pq,scope))
      elif msg_type == MessageType.CLEAR_LINKS:
        scope.target = msg_dict["Subject"]
        pq.put(Priority.HIGH.value,lambda i: Events.clearLinks(i,pq,scope))
      elif msg_type == MessageType.DELETE_SUBJECT:
        scope.target = msg_dict["Subject"]
        pq.put(Priority.HIGH.value,lambda i: Events.deleteSubject(i,pq,scope))
      else:
        pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"Unexpected message type",scope,
                                                     lambda j: Events.die(j,pq,scope)))
    pq.put(i,lambda i: Events.readUntilMessageEnd(i,pq,scope,
	lambda j: Events.waitForNextMessage(j,pq,scope)))

  @staticmethod
  def pushFile(i,pq,scope):
    log_this_func()
    assert scope.filename
    assert scope.curpart == 0
    assert scope.endpart == 0
    assert scope.stream
    localpath = os.path.join(scope.cd,scope.filename)
    try:
      if not db.getObject(localpath):
        pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,
                                                 "Object does not exist in database",scope,
                                                 lambda j: Events.die(j,pq,scope)))
        return
      scope.fd = db.readObject(localpath)
    except DatabaseError as e:
      pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,str(e),scope,
                                                     lambda j: Events.die(j,pq,scope)))
      return
    except IOError:
      pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"Error reading file",scope,
                                                 lambda j: Events.die(j,pq,scope)))
      return
    log("Opened '{}' for reading".format(localpath))
    pq.put(Priority.HIGH.value,lambda i: Events.sendFilePart(i,pq,scope))

  @staticmethod
  def pullFile(dq,scope):
    log_this_func()
    assert scope.filename
    assert scope.curpart
    assert scope.endpart
    assert scope.stream
    if scope.curpart != 0:
      pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"Push must start at zero.",scope,
                                                 lambda j: Events.die(j,pq,scope)))
    elif scope.endpart <= 0:
      pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"File must have a block.",scope,
                                                 lambda j: Events.die(j,pq,scope)))
    else:
      localpath = os.path.join(scope.cd,scope.filename)
      try:
        if db.getObject(localpath):
          pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(
            i,pq,"Object already exists in database",scope,lambda j: Events.die(i,pq,scope)))
          return
        db.insertObject(localpath)
        scope.fd = db.writeObject(localpath)
      except DatabaseError as e:
        pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,str(e),scope,
                                                     lambda j: Events.die(j,pq,scope)))
        return
      except IOError:
        pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"Error writing file",scope,
                                                     lambda j: Events.die(j,pq,scope)))
        return
      log("Opened '{}' for writing after object insertion".format(localpath))
      pq.put(Priority.HIGH.value,lambda i: Events.pullFilePart(i,pq,scope))

  @staticmethod
  def pullFilePart(dq,scope):
    log_this_func()
    assert scope.filename
    assert scope.fd
    assert scope.stream
    assert scope.curpart
    assert scope.endpart
    if scope.in_data:
      try:
        scope.fd.write(scope.in_data)
      except IOError:
        pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"Error writing file",scope,
                                                     lambda j: Events.die(j,pq,scope)))
      return
    else:
      pq.put(Priority.HIGH.value,lambda i: Events.readUntilMessageEnd(i,pq, scope,
                    lambda j: Events.unpackMsgToPullFilePart(j,pq,scope)))
      return
    if scope.curpart == scope.endpart:
      scope.curpart = 0
      scope.endpart = 0
      scope.filename = None
      scope.fd.close()
      scope.fd = None
      scope.in_data = None
      log("All file parts have been recorded.")
      pq.put(Priority.HIGH.value,lambda i: Events.waitForNextMessage(i,pq,scope))
    else:
      pq.put(Priority.HIGH.value,lambda i: Events.readUntilMessageEnd(i,pq, scope,
                    lambda j: Events.unpackMsgToPullFilePart(j,pq,scope)))

  @staticmethod
  def unpackMsgToPullFilePart(i,pq,scope):
    msg_dict = scope.useMsg()
    if msg_dict["MessageType"] != MessageType.XFER_FILE:
      pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"Bad message sequence",scope,
                                                     lambda j: Events.die(j,pq,scope)))
    else:
      scope.in_data = msg_dict["Data"][0:msg_dict["BSize"]]
      next_curpart = msg_dict["CurPart"]
      if next_curpart != scope.curpart:
        pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"Bad message sequence",scope,
                                                     lambda j: Events.die(j,pq,scope)))
        return
      scope.curpart += 1
      pq.put(Priority.HIGH.value,lambda i: Events.pullFilePart(i,pq,scope))

  @staticmethod
  def sendFilePart(i,pq,scope):
    log_this_func()
    assert scope.filename
    assert scope.fd
    assert scope.stream
    assert scope.curpart
    assert scope.endpart
    if scope.curpart > scope.endpart:
      scope.curpart = 0
      scope.endpart = 0
      scope.filename = None
      scope.fd.close()
      scope.fd = None
      log("All file parts have been sent.")
      pq.put(Priority.HIGH.value,lambda i: Events.waitForNextMessage(i,pq,scope))
    else:
      try:
        data = scope.fd.read(_data_size)
      except IOError:
        pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"Error reading file",scope,
                                                     lambda j: Events.die(j,pq,scope)))
        return
      scope.out_data = strategies[(MessageClass.PRIVATE_MSG,MessageType.XFER_FILE)].build([
        data,scope.curpart,len(data)],scope.stream,scope.hmacf)
      scope.curpart += 1
      Events.sendMessage(Priority.HIGH,pq,scope,lambda j: Events.sendFilePart(j,pq,scope))

  @staticmethod
  def authenticate(i,pq,scope):
    assert(scope.target)
    assert(scope.salt)
    try:
      target_entry = db.getSubject(scope.target)
      if target_entry:
        scope.key = hashlib.pbkdf2_hmac("sha1",target_entry.password.encode(
          "UTF-8",errors="ignore"),scope.salt,_hash_rounds, dklen=256)
        scope.stream = RC4(scope.key)
        scope.hmacf = make_hmacf(scope.key)
        scope.out_data = strategies[(MessageClass.PRIVATE_MSG,MessageType.CONFIRM_AUTH)].build([
          target_entry.subject],scope.stream,scope.hmacf)
        scope.subject = target_entry.subject
      else:
        scope.out_data = strategies[(MessageClass.PUBLIC_MSG,MessageType.REJECT_AUTH)].build()
        scope.key = None
        scope.stream = None
        scope.hmacf = None
      Events.sendMessage(Priority.HIGH,pq,scope,lambda j: Events.waitForNextMessage(j,pq,scope))
    except DatabaseError as e:
      pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,str(e),scope,
                                                     lambda j: Events.die(j,pq,scope)))
    except BadMessageError:
      pq.put(Priority.HIGH.value,lambda i: Events.replyErrorMessage(i,pq,"BadMessageError",scope,
                                                     lambda j: Events.die(j,pq,scope)))
      
  @staticmethod
  def replyErrorMessage(i,pq,message,scope,next):
    log_this_func()
    log("Sent error message: %s" % message)
    if scope.stream:
      scope.out_data = strategies[(MessageClass.PRIVATE_MSG,MessageType.ERROR_SERVER)].build(message,
                                                                      scope.stream,scope.hmacf)
    else:
      scope.out_data = strategies[(MessageClass.PUBLIC_MSG,MessageType.ERROR_SERVER)].build(message)
    Events.sendMessage(Priority.HIGH.value,pq,scope,lambda i: next(i))

  @staticmethod
  def die(i,pq,scope):
    log_this_func()
    if scope.stream:
      scope.out_data = strategies[(MessageClass.PRIVATE_MSG,MessageType.DIE)].build()
    else:
      scope.out_data = strategies[(MessageClass.PUBLIC_MSG,MessageType.DIE)].build()
    Events.sendMessage(Priority.HIGH,pq,scope,lambda i: scope.socket.close())

  @staticmethod
  def idle(i,pq):
    pq.put(Priority.IDLE.value,lambda i: Events.idle(i,pq))
