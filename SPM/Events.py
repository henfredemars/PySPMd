from .. import log, __version__, _max_msg_size

from collections import namedtuple
from time import time
import inspect

from Messages.MessageStrategies import strategies

#Events and shared event data

ClientData = namedtuple("ClientData",[
	"socket",
	"msg",
	"buf",
	"subject",      #authenticated
	"stream",       #stream cipher object
	"lastreadtime"  #system time in ms since last call to read part
	"blocktime",    #time to spend blocked while reading message part
	])

#Utility functions (for code readability), time units are in ms
log_this_func = lambda: log(inspect.stack()[1][3])

def init_lastreadtime(scope):
  if scope.lastreadtime is None:
    scope.lastreadtime = time()

def update_blocktime(scope):
  init_lastreadtime(scope)
  ct = time()
  scope.blocktime = next_block_time(scope.blocktime,ct-scope.lastreadtime)
  scope.lastreadtime = ct
  scope.socket.settimeout(scope.blocktime)

def next_block_time(last_time,call_delta,target_depth=700,precision=10):
  if call_delta > target_depth:
    return last_time//2
  return last_time+precision

def scan_for_message_and_divide_if_finished(scope):
  if "\n" in scope.buf:
    split_buf = scope.buf.split("\n")
    scope.msg = split_buf[0].strip()
    scope.buf = ''.join(split_buf[1:])

class Events:

  def __init__(self,dq):
    self.dq = dq

  def acceptClient(self,socket):
    log_this_func()
    addr = socket.getpeername()
    print("Accepted connection from %s:%i" % addr)
    scope = ClientData(socket,None,[],None,None,None,0)
    self.dq.append(lambda: Events.readUntilMessageEnd(self,scope,
	lambda: Events.checkHelloAndReply(self,scope)))

  def readUntilMessageEnd(self,scope,next):
    log_this_func()
    if scope.buf:
      scan_for_message_and_divide_if_finished(scope)
    if scope.msg:
     log("Got full message")
     self.dq.append(lambda: next())
    else:
      self.dq.append(lambda: Events.readMessagePart(self,scope,
	lambda: Events.readUntilMessageEnd(self,scope,next)))

  def readMessagePart(self,scope,next):
    log_this_func()
    update_blocktime(scope)
    scope.buf.append(scope.socket.recv(4096))
    if len(scope.buf) > _max_msg_size:
      self.dq.append(lambda: Events.replyErrorMessage(self,"Message too large.",scope,lambda: Events.die(self,scope)))
    else:
      self.dq.append(lambda: next())

  def checkHelloAndReply(self,scope):
    log_this_func()
    assert(scope.msg)
    msg = scope.msg.split()
    if not msg[0] in strategies or not msg[0]=="HELLO_CLIENT":
      self.dq.append(lambda: Events.replyErrorMessage(self,"Unknown message type.",scope,lambda: Events.die(self,scope)))
      return
    args_dict = strategies[msg[0]].parse(msg)
    log("Client reported version: %s" % args_dict["Version"])
    if str(__version__) != args_dict["Version"]:
      self.dq.append(lambda: Events.replyErrorMessage(self,"Version mismatch.",scope,lambda: Events.die(self,scope)))
      return
    self.dq.append(lambda: Events.waitForNextMessage(self,scope))
    scope.buf = []
    scope.msg = None

  def waitForNextMessage(self,scope):
    while "\n" in scope.buf:
      scan_for_message_and_divide_if_finished(scope)
      #TODO switch on all possible messages
    self.dq.append(lambda: Events.readUntilMessageEnd(self,scope,
	lambda: Events.waitForNextMessage(self,scope)))
