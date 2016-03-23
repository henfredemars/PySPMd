
import asyncio
import hashlib
import os

from . import __version__, _msg_size, _hash_rounds, _data_size
from SPM.Util import log

from SPM.Messages import MessageStrategy, MessageClass, MessageType
from SPM.Messages import BadMessageError
from SPM.Database import DatabaseError
from SPM.Tickets import Ticket, BadTicketError
from SPM.Stream import RC4, make_hmacf
from SPM.Status import Status

strategies = MessageStrategy.strategies

db = None #Initialized before server

class Protocol(asyncio.Protocol):

  def __init__(self,loop):
    self.loop = loop
    self.peerinfo = None
    self.transport = None
    self.status = Status.NORMAL
    self.buf = bytearray()
    self.subject = None
    self.stream = None
    self.hmacf = None
    self.fd = None
    self.cd = "/"
    self.write_lock = asyncio.Lock()

  def pause_writing(self):
    self.loop.create_task(self.write_enable.acquire())

  def resume_writing(self):
    self.write_enable.release()

  async def sendall(self,data):
    await self.write_lock.acquire()
    self.transport.write(data)
    self.write_lock.release()

  def connection_made(self,transport):
    self.transport = transport
    self.transport.set_write_buffer_limits(500000,0)
    self.peerinfo = transport.get_extra_info("peername")
    log("Connection from %s:%s" % self.peerinfo)

  def connection_lost(self,exc):
    if exc:
      log("Lost connection with %s" % self.peerinfo[0])
    else:
      log("%s connection closed" % self.peerinfo[0])

  def data_received(self,data):
    self.buf.extend(data)
    while len(self.buf) >= _msg_size:
      self.loop.create_task(self.dispatch_msg_block(self.buf[0:_msg_size]))
      self.buf = self.buf[_msg_size:]

  async def dispatch_msg_block(self,msg_block):
    try:
      msg_dict = MessageStrategy.parse(msg_block,self.stream,self.hmacf)
    except BadMessageError:
      self.sendError("BadMessageError")
      return
    msg_type = msg_dict["MessageType"]
    log(str(msg_type))
    if msg_type == MessageType.HELLO_CLIENT:
      log("Client reported version: %s" % msg_dict["Version"])
      if __version__ != msg_dict["Version"]:
        self.sendError("Version Mismatch")
        return
      out_data = strategies[(MessageClass.PUBLIC_MSG,MessageType.HELLO_SERVER)].build([__version__])
      await self.sendall(out_data)
    elif msg_type == MessageType.DIE:
      self.transport.close()
    elif msg_type == MessageType.AUTH_SUBJECT:
      target = msg_dict["Subject"]
      salt = msg_dict["Salt"]
      try:
        target_entry = db.getSubject(target)
        if target_entry:
          key = hashlib.pbkdf2_hmac("sha1",target_entry.password.encode(
            "UTF-8",errors="ignore"),salt,_hash_rounds, dklen=256)
          self.stream = RC4(key)
          self.hmacf = make_hmacf(key)
          out_data = strategies[(MessageClass.PRIVATE_MSG,MessageType.CONFIRM_AUTH)].build([
            target_entry.subject],self.stream,self.hmacf)
          self.subject = target_entry.subject
        else:
          out_data = strategies[(MessageClass.PUBLIC_MSG,MessageType.REJECT_AUTH)].build()
          self.stream = None
          self.hmacf = None
          self.subject = None
        await self.sendall(out_data)
      except DatabaseError:
        self.sendError("DatabaseError")
    elif msg_type == MessageType.PUSH_FILE:
      filename = msg_dict["File Name"]
      localpath = os.path.join(self.cd,filename)
      try:
        if db.getObject(localpath):
          self.sendError("Object already exists")
          return
        db.insertObject(localpath)
        self.fd = db.writeObject(localpath)
      except DatabaseError:
        self.sendError("DatabaseError")
        return
      except IOError:
        self.sendError("IOError")
        return
      log("Opened '{}' for writing after object insertion".format(localpath))
      self.status = Status.PULLING
    elif msg_type == MessageType.PULL_FILE:
      filename = msg_dict["File Name"]
      localpath = os.path.join(self.cd,filename)
      try:
        if not db.getObject(localpath):
          self.sendError("Object does not exist")
          return
        self.fd = db.readObject(localpath)
      except DatabaseError:
        self.sendError("DatabaseError")
        return
      except IOError:
        self.sendError("IOError")
        return
      log("Opened '{}' for reading".format(localpath))
      self.status = Status.PUSHING
      data = self.fd.read(_data_size)
      while data:
        out_data = strategies[(MessageClass.PRIVATE,MessageType.XFER_FILE)].build(
                                [data,len(data)],self.stream,self.hmacf)
        await self.sendall(out_data)
        data = self.fd.read(_data_size)
      await self.sendall(strategies[(MessageClass.PRIVATE,MessageType.TASK_DONE)].build(
                                None,self.stream,self.hmacf))
      self.status = Status.NORMAL
    elif msg_type == MessageType.XFER_FILE:
      if self.status == Status.PULLING:
        assert(self.fd)
        self.fd.write(msg_dict["Data"][msg_dict["BSize"]])
      else:
        self.sendError("Ambiguous message sequence")
    elif msg_type == MessageType.TASK_DONE:
      if self.fd:
        self.fd.close()
      self.fd = None
      self.status = Status.Normal
    else:
      self.sendError("Unexpected message type")


