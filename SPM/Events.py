from . import __version__, _max_msg_size
from SPM.Util import log

from time import time as time_sec
from time import sleep
import inspect
import socket

from SPM.Messages import MessageStrategy

strategies = MessageStrategy.strategies

#Events and shared event data

class ClientData:
  def __init__(self,socket):
    self.socket = socket
    self.msg = None
    self.buf = bytearray()
    self.subject = None
    self.stream = None
    self.lastreadtime = None
    self.blocktime = 0

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
  if b"\n" in scope.buf:
    split_buf = scope.buf.split(b"\n")
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
    log_this_func()
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
    log_this_func()
    update_blocktime(scope)
    try:
      scope.buf.extend(bytearray(scope.socket.recv(4096)))
      sleep(scope.blocktime/1000)
    except socket.timeout:
      pass
    if len(scope.buf) > _max_msg_size:
      dq.append(lambda: Events.replyErrorMessage(dq,"Message too large.",scope,lambda: Events.die(dq,scope)))
    else:
      dq.append(lambda: next())

  @staticmethod
  def checkHelloAndReply(dq,scope):
    log_this_func()
    assert(scope.msg)
    msg = scope.msg.split()
    if not msg[0] in strategies or not msg[0]=="HELLO_CLIENT":
      dq.append(lambda: Events.replyErrorMessage(dq,"Unknown message type.",scope,lambda: Events.die(dq,scope)))
      return
    args_dict = strategies[msg[0]].parse(msg)
    log("Client reported version: %s" % args_dict["Version"])
    if str(__version__) != args_dict["Version"]:
      dq.append(lambda: Events.replyErrorMessage(dq,"Version mismatch.",scope,lambda: Events.die(dq,scope)))
      return
    scope.socket.sendall(strategies["HELLO_SERVER"].build([__version__]))
    dq.append(lambda: Events.waitForNextMessage(dq,scope))
    scope.buf = []
    scope.msg = None

  @staticmethod
  def waitForNextMessage(dq,scope):
    while "\n" in scope.buf:
      scan_for_message_and_divide_if_finished(scope)
      #TODO switch on all possible messages
    dq.append(lambda: Events.readUntilMessageEnd(dq,scope,
	lambda: Events.waitForNextMessage(dq,scope)))

  @staticmethod
  def replyErrorMessage(dq,message,scope,next):
    log_this_func()
    scope.socket.sendall(message.encode(encoding="UTF-8"))
    dq.append(lambda: next())

  @staticmethod
  def die(dq,scope):
    log_this_func()
    scope.socket.sendall(strategies["DIE"].build())
    scope.socket.close()
    
