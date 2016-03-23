from . import __version__, _msg_size, _hash_rounds, _data_size
from SPM.Util import log

import os
import inspect
import socket
import hashlib

from SPM.Messages import MessageStrategy, MessageClass, MessageType
from SPM.Messages import BadMessageError
from SPM.Database import DatabaseError
from SPM.Tickets import Ticket, BadTicketError
from SPM.Stream import RC4, make_hmacf

strategies = MessageStrategy.strategies

#Events and shared event data

class ClientData:
  
  def __init__(self,socket):
    self.status = Status.RUN      #Client execution status
    self.resume = None
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

      elif msg_type == MessageType.PULL_FILE:
        scope.filename = msg_dict["File Name"]
        scope.curpart = 0
        scope.endpart = 0
        dq.append(lambda: Events.pushFile(dq,scope))
        return #No parallel dispatch
      elif msg_type == MessageType.PUSH_FILE:
        scope.filename = msg_dict["File Name"]
        scope.in_data = None
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
      else:
         dq.append(lambda: Events.replyErrorMessage(dq,"Unexpected message type",scope,
                                                     lambda: Events.die(dq,scope)))
    dq.append(lambda: Events.readUntilMessageEnd(dq,scope,
	lambda: Events.waitForNextMessage(dq,scope)))

      
  @staticmethod
  def replyErrorMessage(dq,message,scope,next):
    log_this_func()
    log("Sent error message: %s" % message)
    if scope.stream:
      scope.out_data = strategies[(MessageClass.PRIVATE_MSG,MessageType.ERROR_SERVER)].build(message,
                                                                      scope.stream,scope.hmacf)
    else:
      scope.out_data = strategies[(MessageClass.PUBLIC_MSG,MessageType.ERROR_SERVER)].build(message)
    Events.sendMessage(dq,scope,lambda: next())

  @staticmethod
  def die(dq,scope):
    log_this_func()
    if scope.stream:
      scope.out_data = strategies[(MessageClass.PRIVATE_MSG,MessageType.DIE)].build()
    else:
      scope.out_data = strategies[(MessageClass.PUBLIC_MSG,MessageType.DIE)].build()
    Events.sendMessage(dq,scope,lambda: Events.markDyingAndClose(dq,scope))

  @staticmethod
  def markDyingAndClose(dq,scope):
    scope.status = Status.DYING
    scope.socket.close()
