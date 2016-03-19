
import socket
import hashlib
import math
from os import urandom

from . import __version__, _msg_size, _hash_rounds, _data_size

from SPM.Util import log
from SPM.Messages import MessageStrategy, MessageClass, MessageType, BadMessageError
from SPM.Stream import RC4, make_hmacf

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
    while len(self.buf) < _msg_size:
      self.buf.extend(self.socket.recv(4096))
    msg_dict = MessageStrategy.parse(self.buf[0:_msg_size],self.stream,self.hmacf)
    self.buf = self.buf[_msg_size:]
    return msg_dict

  def connected(self):
    return self.connected

  def greetServer(self):
    self.socket.connect((self.addr,self.port))
    self.socket.sendall(strategies[(MessageClass.PUBLIC_MSG,MessageType.HELLO_CLIENT)].build([__version__]))
    msg_dict = self.readMessage()
    if msg_dict["MessageType"] != MessageType.HELLO_SERVER:
      self.socket.close()
      raise ClientError("Server did not reply as expected.")
    else:
      if msg_dict["Version"] != __version__:
        self.socket.close()
        raise ClientError("Server version mismatch.")
    self.connected = True

  def authenticate(self,subject,password):
    print("Authenticating...")
    if not self.connected:
      raise ClientError("Not connected to a server.")
    salt = urandom(32)
    self.key = hashlib.pbkdf2_hmac("sha1",password.encode("UTF-8"),salt,_hash_rounds,dklen=256)
    self.hmacf = make_hmacf(self.key)
    self.stream = RC4(self.key)
    self.subject = subject
    self.socket.sendall(strategies[(MessageClass.PUBLIC_MSG,MessageType.AUTH_SUBJECT)].build([subject,salt]))
    try:
      msg_dict = self.readMessage()
      msg_type = msg_dict["MessageType"]
    except BadMessageError as e:
      print(str(e))
      self.resetConnection()
      return False
    if msg_type == MessageType.CONFIRM_AUTH:
      print("Authentication success.")
      return True
    elif msg_type == MessageType.REJECT_AUTH:
      print("The server explicitly rejected us.")
      self.key = None
      self.hmacf = None
      self.subject = None
      self.stream = None
      return False
    else:
      print("Unexpected message from the server (bad password)")
      self.resetConnection()
      return False

  def sendFile(self,remotename,localpath):
    if not os.path.isfile(localpath):
      raise ClientError("File does not exist.")
    if not self.connected:
      raise ClientError("No active connection.")
    if not self.subject or not self.stream:
      raise ClientError("Not authenticated.")
    f_size = os.path.getsize(localpath)
    f_parts = math.ceil(f_size/_data_size)
    self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.PUSH_FILE)].build(
                        [os.path.basename(remotename),f_parts-1],self.stream,self.hmacf))
    with open(path,"rb") as fd:
      for curpart in range(f_parts):
        print("Sending part {} of {}...".format(curpart,f_parts-1))
        data = fd.read(_data_size)
        self.socket.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.XFER_FILE)].build(
          [data,curpart,len(data)],self.stream,self.hmacf))
        

  def resetConnection(self):
    self.stream = None
    self.hmacf = None
    self.leaveServer()
    self.__init__(self.addr,self.port)
    self.greetServer()

  def leaveServer(self):
    if not self.connected:
      return
    self.socket.sendall(strategies[(MessageClass.PUBLIC_MSG,MessageType.DIE)].build(None,self.stream,self.hmacf))
    self.socket.close()
    self.__init__(self.addr,self.port)
