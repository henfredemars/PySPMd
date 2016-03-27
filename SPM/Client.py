
import socket
import hashlib
import os

from . import __version__, _msg_size, _hash_rounds, _data_size

from SPM.Messages import MessageStrategy, MessageClass, MessageType, BadMessageError
from SPM.Stream import RC4, make_hmacf
from SPM.Tickets import Ticket, BadTicketError
from SPM.Util import log

strategies = MessageStrategy.strategies

#Server

class ClientError(RuntimeError):
  def __init__(self,msg):
    super().__init__(msg)

class Client():

  def __init__(self,addr,port):
    self.addr = addr
    self.port = port
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connected = False
    self.key = None
    self.stream = None
    self.hmacf = None
    self.subject = None
    self.buf = bytearray()

  def readMessage(self):
    """Perform a buffered read from the socket"""
    while len(self.buf) < _msg_size:
      self.buf.extend(self.socket.recv(4096))
    msg_dict = MessageStrategy.parse(self.buf[0:_msg_size],self.stream,self.hmacf)
    self.buf = self.buf[_msg_size:]
    return msg_dict

  def checkOkay(self):
    msg_dict = self.readMessage()
    if msg_dict["MessageType"] == MessageType.ERROR_SERVER:
      raise ClientError("ErrorServer: %s" % msg_dict["Error Message"])

  def connected(self):
    """Check if the client has an active connection"""
    return self.connected

  def greetServer(self):
    """Send the server greeting and establish compatible client and server versions"""
    self.socket.connect((self.addr,self.port))
    self.socket.sendall(strategies[(MessageClass.PUBLIC_MSG,MessageType.HELLO_CLIENT)].build([__version__]))
    msg_dict = self.readMessage()
    if msg_dict["MessageType"] != MessageType.HELLO_SERVER:
      self.socket.close()
      raise ClientError("Server did not reply as expected")
    else:
      if msg_dict["Version"] != __version__:
        self.socket.close()
        raise ClientError("Server version mismatch")
    log("Successfully opened a new unauthenticated connection.")
    self.connected = True

  def authenticate(self,subject,password):
    """Authenticate as a subject and establish encryption"""
    log("Authenticating...")
    if not self.connected:
      raise ClientError("Not connected to a server")
    salt = os.urandom(32)
    self.key = hashlib.pbkdf2_hmac("sha1",password.encode("UTF-8"),salt,_hash_rounds,dklen=256)
    self.hmacf = make_hmacf(self.key)
    self.stream = RC4(self.key)
    self.subject = subject
    self.socket.sendall(strategies[(MessageClass.PUBLIC_MSG,MessageType.AUTH_SUBJECT)].build([subject,salt]))
    try:
      msg_dict = self.readMessage()
      msg_type = msg_dict["MessageType"]
    except BadMessageError as e:
      log(str(e))
      log("Probably your login information was incorrect.")
      self.resetConnection()
      return False
    if msg_type == MessageType.CONFIRM_AUTH:
      log("Authentication success.")
      return True
    else:
      log("Unexpected message from the server (bad login information)")
      self.resetConnection()
      return False

  def listSubjects(self):
    """List all valid subjects on the server (requires authentication)"""
    if not self.connected:
      raise ClientError("Not connected to a server")
    if not self.stream:
      raise ClientError("Cannot list subjects unless authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.LIST_SUBJECT_CLIENT)].build(
                        None,self.stream,self.hmacf))
    subjects = []
    msg_dict = self.readMessage()
    while msg_dict["MessageType"] == MessageType.LIST_SUBJECT_SERVER:
      subjects.extend(msg_dict["Subject"])
      msg_dict = self.readMessage()
    if msg_dict["MessageType"] == MessageType.ERROR_SERVER:
      raise ClientError("ServerError: %s" % str(msg_dict["Error Message"]))
    elif msg_dict["MessageType"] != MessageType.OKAY:
      raise ClientError("Unexpected message sequence")
    return [subject for subject in subjects if subject]

  def listObjects(self):
    """List all valid objects on the server (requires authentication)"""
    if not self.connected:
      raise ClientError("Not connected to a server")
    if not self.stream:
      raise ClientError("Cannot list objects unless authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.LIST_OBJECT_CLIENT)].build(
                        None,self.stream,self.hmacf))
    objects = []
    msg_dict = self.readMessage()
    while msg_dict["MessageType"] == MessageType.LIST_OBJECT_SERVER:
      objects.extend(msg_dict["File"])
      msg_dict = self.readMessage()
    if msg_dict["MessageType"] == MessageType.ERROR_SERVER:
      raise ClientError("ServerError: %s" % str(msg_dict["Error Message"]))
    elif msg_dict["MessageType"] != MessageType.OKAY:
      raise ClientError("Unexpected message sequence")
    return [object for object in objects if object]

  def cd(self,remotepath):
    """Change virtual remote path on the server"""
    if not self.connected:
      raise ClientError("Not connected to a server")
    if not self.stream:
      raise ClientError("Must be authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.CD)].build(
                        [remotepath],self.stream,self.hmacf))
    msg_dict = self.readMessage()
    if msg_dict["MessageType"] == MessageType.ERROR_SERVER:
      raise ClientError("ServerError: %s" % msg_dict["Error Message"])

  def pwd(self):
    """Get current remote working directory"""
    if not self.connected:
      raise ClientError("Not connected to a server")
    if not self.stream:
      raise ClientError("Must be authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.GET_CD)].build(
                        None,self.stream,self.hmacf))
    msg_dict = self.readMessage()
    if msg_dict["MessageType"] == MessageType.CD:
      return msg_dict["Path"]
    else:
      raise ClientError("Unexpected message from the server")

  def giveTicketSubject(self,subject,ticket,target,isObject):
    """Force a subject to receive a ticket. Requires a super authenticated connection"""
    if not self.connected:
      raise ClientError("Not connected to a server")
    if not self.stream:
      raise ClientError("Must be authenticated")
    if not all([subject,ticket,target]):
      raise ClientError("Missing a subject")
    if not isinstance(ticket,Ticket):
      try:
        ticket = Ticket(ticket)
      except BadTicketError:
        raise ClientError("Bad ticket")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.GIVE_TICKET_SUBJECT)]
                        .build([subject,repr(ticket),target,isObject],self.stream,self.hmacf))
    msg_dict = self.readMessage()
    if msg_dict["MessageType"] == MessageType.ERROR_SERVER:
      raise ClientError("ServerError: %s" % msg_dict["Error Message"])

  def takeTicketSubject(self,subject,ticket,target,isObject):
    """Force a subject to drop a ticket. Requires a super authenticated connection"""
    if not self.connected:
      raise ClientError("Not connected to a server")
    if not self.stream:
      raise ClientError("Must be authenticated")
    if not all([subject,ticket,target]):
      raise ClientError("Missing a subject")
    if not isinstance(ticket,Ticket):
      try:
        ticket = Ticket(ticket)
      except BadTicketError:
        raise ClientError("Bad ticket")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.TAKE_TICKET_SUBJECT)]
                        .build([subject,repr(ticket),target,isObject],self.stream,self.hmacf))
    msg_dict = self.readMessage()
    if msg_dict["MessageType"] == MessageType.ERROR_SERVER:
      raise ClientError("ServerError: %s" % msg_dict["Error Message"])

  def xferTicketSubject(self,subject1,subject2,ticket,target,isObject):
    """Ask a subject to transfer an existing ticket. Requires an authenticated connection"""
    if not self.connected:
      raise ClientError("Not connected to a server")
    if not self.stream:
      raise ClientError("Must be authenticated")
    if not all([subject1,subject2,ticket,target]):
      raise ClientError("Missing a subject")
    if not isinstance(ticket,Ticket):
      try:
        ticket = Ticket(ticket)
      except BadTicketError:
        raise ClientError("Bad ticket")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.XFER_TICKET_SUBJECT)]
                        .build([subject1,subject2,repr(ticket),target,isObject],self.stream,self.hmacf))
    msg_dict = self.readMessage()
    if msg_dict["MessageType"] == MessageType.ERROR_SERVER:
      raise ClientError("ServerError: %s" % msg_dict["Error Message"])

  def sendFile(self,remotename,localpath):
    """Send a file from a localpath to a remotepath"""
    if not os.path.isfile(localpath):
      raise ClientError("File does not exist")
    if not self.connected:
      raise ClientError("No active connection")
    if not self.subject or not self.stream:
      raise ClientError("Not authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.PUSH_FILE)].build(
                        [remotename],self.stream,self.hmacf))
    self.checkOkay()
    with open(localpath,"rb") as fd:
      data = fd.read(_data_size)
      while data:
        self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.XFER_FILE)].build(
          [data,len(data)],self.stream,self.hmacf))
        data = fd.read(_data_size)
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.OKAY)].build(
          None,self.stream,self.hmacf))

  def getFile(self,remotename,localpath):
    """Download a file from a remote to a local path"""
    if os.path.isfile(localpath):
      raise ClientError("File exists")
    if not self.connected:
      raise ClientError("No active connection")
    if not self.subject or not self.stream:
      raise ClientError("Not authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.PULL_FILE)].build(
                        [remotename],self.stream,self.hmacf))
    self.checkOkay()
    with open(localpath,"wb") as fd:
      msg_dict = self.readMessage()
      while msg_dict["MessageType"] == MessageType.XFER_FILE:
        fd.write(msg_dict["Data"][:msg_dict["BSize"]])
        msg_dict = self.readMessage()
      if msg_dict["MessageType"] == MessageType.ERROR_SERVER:
        raise ClientError("ServerError: %s" % str(msg_dict["Error Message"]))
      elif msg_dict["MessageType"] != MessageType.OKAY:
        raise ClientError("Unexpected message sequence")

  def deleteFile(self,remotename):
    """Delete a file from a remote path"""
    if not self.connected:
      raise ClientError("No active connection")
    if not self.subject or not self.stream:
      raise ClientError("Not authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.DELETE_PATH)].build(
                        [remotename],self.stream,self.hmacf))
    self.checkOkay()

  def makeDirectory(self,remotename):
    """Create a directory on the remote server"""
    if not self.connected:
      raise ClientError("No active connection")
    if not self.subject or not self.stream:
      raise ClientError("Not authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.MAKE_DIRECTORY)].build(
                        [remotename],self.stream,self.hmacf))
    self.checkOkay()

  def makeSubject(self,subject,stype,password):
    """Create a new subject on the server"""
    if not self.connected:
      raise ClientError("No active connection")
    if not self.subject or not self.stream:
      raise ClientError("Not authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.MAKE_SUBJECT)].build(
                        [subject,stype,password],self.stream,self.hmacf))
    self.checkOkay()

  def deleteSubject(self,subject):
    """Delete a subject from the server"""
    if not self.connected:
      raise ClientError("No active connection")
    if not self.subject or not self.stream:
      raise ClientError("Not authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.DELETE_SUBJECT)].build(
                        [subject],self.stream,self.hmacf))
    self.checkOkay()

  def makeLink(self,subject1,subject2):
    """Create a transfer link between two subjects"""
    if not self.connected:
      raise ClientError("No active connection")
    if not self.subject or not self.stream:
      raise ClientError("Not authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.MAKE_LINK)].build(
                        [subject1,subject2],self.stream,self.hmacf))
    self.checkOkay()

  def makeFilter(self,type1,type2,ticket):
    """Create a type filter to allow rights transfers"""
    if not self.connected:
      raise ClientError("No active connection")
    if not self.subject or not self.stream:
      raise ClientError("Not authenticated")
    ticket = str(ticket)
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.MAKE_FILTER)].build(
                        [type1,type2,ticket],self.stream,self.hmacf))
    self.checkOkay()

  def deleteFilter(self,type1,type2,ticket):
    """Delete a type filter for rights transfers"""
    if not self.connected:
      raise ClientError("No active connection")
    if not self.subject or not self.stream:
      raise ClientError("Not authenticated")
    ticket = str(ticket)
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.DELETE_FILTER)].build(
                        [type1,type2,ticket],self.stream,self.hmacf))
    self.checkOkay()

  def clearLinks(self,subject):
    """Create a new subject on the server"""
    if not self.connected:
      raise ClientError("No active connection")
    if not self.subject or not self.stream:
      raise ClientError("Not authenticated")
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.CLEAR_LINKS)].build(
                        [subject],self.stream,self.hmacf))
    self.checkOkay()

  def resetConnection(self):
    self.stream = None
    self.hmacf = None
    self.leaveServer()
    self.__init__(self.addr,self.port)
    self.greetServer()

  def leaveServer(self):
    if not self.connected:
      return
    self.close()
    self.__init__(self.addr,self.port)

  def close(self):
    if not self.connected:
      return
    self.socket.sendall(strategies[(MessageClass.PUBLIC_MSG,MessageType.DIE)].build(None,self.stream,self.hmacf))
    self.socket.close()

