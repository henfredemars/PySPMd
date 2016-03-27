
import asyncio
import hashlib
import random
import os

from . import __version__, _msg_size, _hash_rounds, _data_size, _min_pass_len
from . import _base_login_delay, _lss_count, _ls_count
from SPM.Util import log, chunks, expandPath

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
    self.pwd = os.path.join(os.getcwd(),db.root)
    self.write_lock = asyncio.Lock()

  def pause_writing(self):
    self.loop.create_task(self.write_enable.acquire())

  def resume_writing(self):
    self.write_enable.release()

  async def sendall(self,data):
    await self.write_lock.acquire()
    self.transport.write(data)
    self.write_lock.release()

  async def sendError(self,msg):
    if self.stream:
      msg = strategies[(MessageClass.PRIVATE_MSG,MessageType.ERROR_SERVER)].build(
                            [msg],self.stream,self.hmacf)
    else:
      msg = strategies[(MessageClass.PUBLIC_MSG,MessageType.ERROR_SERVER)].build([msg])
    try:
      await self.sendall(msg)
    except IOError:
      pass

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

  async def sendOkay(self):
    await self.sendall(strategies[(MessageClass.PRIVATE_MSG,MessageType.OKAY)].build(
                                None,self.stream,self.hmacf))

  def data_received(self,data):
    self.buf.extend(data)
    while len(self.buf) >= _msg_size:
      self.loop.create_task(self.dispatch_msg_block(self.buf[0:_msg_size]))
      self.buf = self.buf[_msg_size:]

  async def dispatch_msg_block(self,msg_block):
    #Leave immidiately if the transport is closing
    if self.transport.is_closing():
      return
    #Try to parse the (possibly evil) message
    try:
      msg_dict = MessageStrategy.parse(msg_block,self.stream,self.hmacf)
    except BadMessageError:
      await self.sendError("BadMessageError")
      return
    #Record message information
    msg_type = msg_dict["MessageType"]
    log(str(msg_type))
    #Big, ugly switch to handle the message
    if msg_type == MessageType.HELLO_CLIENT:
      log("Client reported version: %s" % msg_dict["Version"])
      if __version__ != msg_dict["Version"]:
        await self.sendError("Version Mismatch")
      else:
        out_data = strategies[(MessageClass.PUBLIC_MSG,MessageType.HELLO_SERVER)].build([__version__])
        await self.sendall(out_data)
    elif msg_type == MessageType.DIE:
      #Immidiately close the connection
      self.transport.close()
    elif msg_type == MessageType.AUTH_SUBJECT:
      target = msg_dict["Subject"]
      salt = msg_dict["Salt"]
      if not target or not salt:
        await self.sendError("Missing target or salt")
        return
      #Resist timing attacks on the login process
      await asyncio.sleep(_base_login_delay + random.random())
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
        else: #This is our way of rejecting the login
          key = os.urandom(256)
          self.stream = RC4(key)
          self.hmacf = make_hmacf(key)
          out_data = strategies[(MessageClass.PRIVATE_MSG,MessageType.CONFIRM_AUTH)].build([
            target],self.stream,self.hmacf)
          self.subject = None
        await self.sendall(out_data)
      except DatabaseError:
        await self.sendError("DatabaseError")
    elif msg_type == MessageType.PUSH_FILE:
      filename = msg_dict["File Name"]
      localpath = expandPath("/",self.cd,filename)
      try:
        if db.getObject(localpath):
          await self.sendError("Object already exists")
          return
        db.insertObject(localpath)
        if self.fd:
          self.fd.close()
        self.fd = db.writeObject(localpath)
      except DatabaseError:
        await self.sendError("DatabaseError")
        return
      except IOError:
        await self.sendError("IOError")
        return
      await self.sendOkay()
      log("Opened '{}' for writing after object insertion".format(localpath))
      self.status = Status.PULLING
    elif msg_type == MessageType.PULL_FILE:
      filename = msg_dict["File Name"]
      localpath = expandPath("/",self.cd,filename)
      abs_path = expandPath(self.pwd,self.cd,filename)
      if not os.path.isfile(abs_path):
        await self.sendError("Not a valid file for reading")
        return
      try:
        if not db.getObject(localpath):
          await self.sendError("Object does not exist")
          return
        if self.fd:
          self.fd.close()
        self.fd = db.readObject(localpath)
      except DatabaseError:
        await self.sendError("DatabaseError")
        return
      except IOError:
        await self.sendError("IOError")
        return
      log("Opened '{}' for reading".format(localpath))
      self.status = Status.PUSHING
      await self.sendOkay()
      data = self.fd.read(_data_size)
      while data:
        out_data = strategies[(MessageClass.PRIVATE_MSG,MessageType.XFER_FILE)].build(
                                [data,len(data)],self.stream,self.hmacf)
        await self.sendall(out_data)
        data = self.fd.read(_data_size)
      await self.sendOkay()
      self.status = Status.NORMAL
    elif msg_type == MessageType.XFER_FILE:
      if self.status == Status.PULLING:
        assert(self.fd)
        self.fd.write(msg_dict["Data"][:msg_dict["BSize"]])
      else:
        await self.sendError("Ambiguous message sequence")
    elif msg_type == MessageType.OKAY:
      if self.fd:
        self.fd.close()
      self.fd = None
      self.status = Status.NORMAL
    elif msg_type == MessageType.LIST_SUBJECT_CLIENT:
      subjects = db.getSubjectNames()
      s_lists = chunks(subjects,_lss_count)
      for list in s_lists:
        while len(list) < _lss_count:
          list.append("")
      msgs = map(lambda s_list: strategies[(MessageClass.PRIVATE_MSG,MessageType.LIST_SUBJECT_SERVER)]
                 .build(s_list,self.stream,self.hmacf),s_lists)
      for msg_block in msgs:
        await self.sendall(msg_block)
      await self.sendOkay()
    elif msg_type == MessageType.LIST_OBJECT_CLIENT:
      objects = os.listdir(expandPath(self.pwd,self.cd,""))
      s_lists = chunks(objects,_ls_count)
      for list in s_lists:
        while len(list) < _ls_count:
          list.append("")
      msgs = map(lambda s_list: strategies[(MessageClass.PRIVATE_MSG,MessageType.LIST_OBJECT_SERVER)]
                 .build(s_list,self.stream,self.hmacf),s_lists)
      for msg_block in msgs:
        await self.sendall(msg_block)
      await self.sendOkay()
    elif msg_type == MessageType.GIVE_TICKET_SUBJECT:
      try:
        subject = db.getSubject(msg_dict["Subject"])
        ticket = Ticket(msg_dict["Ticket"])
        isObject = bool(msg_dict["IsObject"])
        if isObject:
          target = expandPath("/",self.cd,msg_dict["Target"])
          if not os.path.exists(expandPath(self.pwd,"/",target)):
            await self.sendError("No such target object")
            return
        else:
          target = db.getSubject(msg_dict["Target"])
          if not target:
            await self.sendError("No such subject")
            return
          target = target.subject
        if not subject:
          await self.sendError("No such subject")
          return
        else:
          subject = subject.subject
      except BadTicketError:
        await self.sendError("BadTicketError")
        return
      except DatabaseError:
        await self.sendError("DatabaseError")
      db.insertRight(subject,ticket,target,isObject)
      await self.sendOkay()
    elif msg_type == MessageType.TAKE_TICKET_SUBJECT:
      try:
        subject = db.getSubject(msg_dict["Subject"])
        ticket = Ticket(msg_dict["Ticket"])
        isObject = bool(msg_dict["IsObject"])
        if isObject:
          target = expandPath("/",self.cd,msg_dict["Target"])
          if not os.path.exists(expandPath(self.pwd,"/",target)):
            await self.sendError("No such target object")
            return
        else:
          target = db.getSubject(msg_dict["Target"])
          if not target:
            await self.sendError("No such subject")
            return
          target = target.subject
        if not subject:
          await self.sendError("No such subject")
          return
        else:
          subject = subject.subject
      except BadTicketError:
        await self.sendError("BadTicketError")
        return
      except DatabaseError:
        await self.sendError("DatabaseError")
      db.deleteRight(subject,ticket,target,isObject)
      await self.sendOkay()
    elif msg_type == MessageType.XFER_TICKET:
      try:
        subject1 = db.getSubject(msg_dict["Subject1"])
        subject2 = db.getSubject(msg_dict["Subject2"])
        ticket = Ticket(msg_dict["Ticket"])
        isObject = bool(msg_dict["IsObject"])
        if isObject:
          target = expandPath("/",self.cd,msg_dict["Target"])
          if not os.path.exists(expandPath(self.pwd,"/",target)):
            await self.sendError("No such target object")
            return
        else:
          target = db.getSubject(msg_dict["Target"])
          if not target:
            await self.sendError("No such subject")
            return
          target = target.subject
        if not subject1 or not subject2:
          await self.sendError("No such subject")
          return
        else:
          subject1 = subject1.subject
          subject2 = subject2.subject
      except BadTicketError:
        await self.sendError("BadTicketError")
        return
      except DatabaseError:
        await self.sendError("DatabaseError")
      db.insertRight(subject2,ticket,target,isObject)
      db.deleteRight(subject1,ticket,target,isObject)
      await self.sendOkay()
    elif msg_type == MessageType.MAKE_DIRECTORY:
      directory = msg_dict["Directory"]
      abs_path = expandPath(self.pwd,self.cd,directory)
      rel_path = expandPath("/",self.cd,directory)
      if os.path.exists(abs_path):
        await self.sendError("Path already exists")
        return
      try:
        db.insertObject(rel_path,True)
        os.makedirs(abs_path)
        await self.sendOkay()
      except DatabaseError:
        await self.sendError("DatabaseError")
    elif msg_type == MessageType.MAKE_SUBJECT:
      try:
        subject = db.getSubject(msg_dict["Subject"])
        stype = msg_dict["Type"]
        password = msg_dict["Password"]
        if len(password) <= _min_pass_len:
          await self.sendError("Password is way too short")
          return
        if subject:
          await self.sendError("Subject already exists")
          return
        if not stype:
          await self.sendError("Subject must have a type")
          return
        db.insertSubject(msg_dict["Subject"],password,stype,False)
        await self.sendOkay()
      except DatabaseError:
        await self.sendError("DatabaseError")
    elif msg_type == MessageType.CD:
      path = msg_dict["Path"]
      abs_path = expandPath(self.pwd,self.cd,path)
      rel_path = expandPath("/",self.cd,path)
      if os.path.isdir(abs_path):
        self.cd = rel_path
        await self.sendOkay()
      else:
        await self.sendError("Path does not appear to exist")
    elif msg_type == MessageType.GET_CD:
      msg_encoded = strategies[(MessageClass.PRIVATE_MSG,MessageType.CD)].build([self.cd],
                                                          self.stream,self.hmacf)
      await self.sendall(msg_encoded)
    elif msg_type == MessageType.MAKE_FILTER:
      type1 = msg_dict["Type1"]
      type2 = msg_dict["Type2"]
      try:
        ticket = Ticket(msg_dict["Ticket"])
      except BadTicketError:
        await self.sendError("BadTicketError")
      db.insertFilter(type1,type2,ticket)
    elif msg_type == MessageType.MAKE_LINK:
      try:
        subject1 = db.getSubject(msg_dict["Subject1"])
        subject2 = db.getSubject(msg_dict["Subject2"])
        if not subject1 or not subject2:
          self.sendError("Subjects must exist")
        else:
          subject1 = subject1.subject
          subject2 = subject2.subject
          db.insertLink(subject1,subject2)
          await self.sendOkay()
      except DatabaseError:
        await self.sendError("DatabaseError")
    elif msg_type == MessageType.DELETE_PATH:
      path = msg_dict["Path"]
      try:
        db.deleteObject(expandPath("/",self.cd,path))
        await self.sendOkay()
      except DatabaseError:
        await self.sendError("DatabaseError")
    elif msg_type == MessageType.CLEAR_LINKS:
      subject = msg_dict["Subject"]
      if not subject:
        await self.sendError("A subject is required")
      else:
        db.clearLinks(subject)
    elif msg_type == MessageType.DELETE_SUBJECT:
      subject = msg_dict["Subject"]
      if not subject:
        await self.sendError("A subject is required")
      else:
        db.deleteSubject(subject)
    else:
      await self.sendError("Unexpected message type")


