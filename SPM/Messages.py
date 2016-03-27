
import struct

from collections import namedtuple
from enum import Enum
from hmac import compare_digest

from SPM.Util import log

from . import _msg_size, _subject_size, _password_size, _lss_count
from . import _file_size, _hash_size, _ticket_size, _ls_count, _type_size
from . import _error_msg_size, _salt_size, _data_size, _file_path_size

#Messages

#Message Format: MessageClass(byte) MessageType(byte)...
TypeInfo = namedtuple("TypeInfo",["bc","fmt","args","codec"])
Codec = namedtuple("Codec",["enc","dec"])

utf_enc = lambda a: str(a).encode(encoding="UTF-8",errors="ignore")
utf_dec = lambda a: (a.decode(encoding="UTF-8",errors="ignore")).strip("\0")
ident   = lambda a: a

class BadMessageError(RuntimeError):
  def __init__(self,message):
    super().__init__(message)
    log("BadMessageError: " + message)

class MessageType(Enum):
  HELLO_SERVER          = TypeInfo(bytes([0]),"!I",("Version",),
                            Codec(lambda a: map(int,a),
                                  lambda a: map(int,a)))
  HELLO_CLIENT          = TypeInfo(bytes([1]),"!I",("Version",),
                            Codec(lambda a: map(int,a),
                                  lambda a: map(int,a)))
  DIE                   = TypeInfo(bytes([2]),None,None,
                            Codec(None,None))
  PULL_FILE             = TypeInfo(bytes([3]),"!{}s".format(_file_path_size),("File Name",),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  PUSH_FILE             = TypeInfo(bytes([4]),"!{}s".format(_file_path_size),("File Name",),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  XFER_FILE             = TypeInfo(bytes([5]),"!{}sH".format(_data_size),("Data","BSize"),
                            Codec(lambda a: (bytes(a[0]),int(a[1])),
                                  lambda a: (bytes(a[0]),int(a[1]))))
  OKAY		= TypeInfo(bytes([6]),None,None,
                            Codec(None,None))
  ERROR_SERVER          = TypeInfo(bytes([7]),"!{}s".format(_error_msg_size),("Error Message",),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  AUTH_SUBJECT          = TypeInfo(bytes([8]),"!{}s{}s".format(_subject_size,_salt_size),("Subject","Salt"),
                            Codec(lambda a: (utf_enc(a[0]),bytes(a[1])),
                                  lambda a: (utf_dec(a[0]),bytes(a[1]))))
  CONFIRM_AUTH          = TypeInfo(bytes([9]),"!{}s".format(_subject_size),("Subject",),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  LIST_SUBJECT_CLIENT   = TypeInfo(bytes([10]),None,None,
                            Codec(None,None))
  LIST_SUBJECT_SERVER   = TypeInfo(bytes([11]),("!"+("{}s".format(_subject_size))*_lss_count),("Subject",)*_lss_count,
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  LIST_OBJECT_CLIENT    = TypeInfo(bytes([12]),None,None,
                            Codec(None,None))
  LIST_OBJECT_SERVER    = TypeInfo(bytes([13]),("!"+("{}s".format(_file_size))*_ls_count),("File",)*_ls_count,
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  GIVE_TICKET_SUBJECT   = TypeInfo(bytes([14]),"!{0}s{1}s{0}sB".format(_subject_size,_ticket_size),
                                   ("Subject","Ticket","Target","IsObject"),
                            Codec(lambda a: (utf_enc(a[0]),utf_enc(a[1]),utf_enc(a[2]),int(a[3])),
                                  lambda a: (utf_dec(a[0]),utf_dec(a[1]),utf_dec(a[2]),int(a[3]))))
  TAKE_TICKET_SUBJECT   = TypeInfo(bytes([15]),"!{0}s{1}s{0}sB".format(_subject_size,_ticket_size),
                                   ("Subject","Ticket","Target","IsObject"),
                            Codec(lambda a: (utf_enc(a[0]),utf_enc(a[1]),utf_enc(a[2]),int(a[3])),
                                  lambda a: (utf_dec(a[0]),utf_dec(a[1]),utf_dec(a[2]),int(a[3]))))
  MAKE_DIRECTORY        = TypeInfo(bytes([16]),"!{}s".format(_file_size),("Directory",),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  MAKE_SUBJECT          = TypeInfo(bytes([17]),"!{}s{}s{}s".format(_subject_size,_type_size,_password_size),("Subject","Type","Password"),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  CD                    = TypeInfo(bytes([18]),"!{}s".format(_file_path_size),("Path",),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  MAKE_FILTER           = TypeInfo(bytes([19]),"!{0}s{0}s{1}s".format(_type_size,_ticket_size),("Type1","Type2","Ticket"),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  MAKE_LINK             = TypeInfo(bytes([20]),"!{0}s{0}s".format(_subject_size),("Subject1","Subject2"),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  DELETE_PATH           = TypeInfo(bytes([21]),"!{}s".format(_file_size),("Path",),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  CLEAR_LINKS           = TypeInfo(bytes([22]),"!{}s".format(_subject_size),("Subject",),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  DELETE_SUBJECT        = TypeInfo(bytes([23]),"!{}s".format(_subject_size),("Subject",),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  XFER_TICKET           = TypeInfo(bytes([24]),"!{0}s{0}s{1}s{0}sB".format(_subject_size,_ticket_size),
                                   ("Subject1","Subject2","Ticket","Target","IsObject"),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))
  GET_CD                = TypeInfo(bytes([25]),None,None,
                            Codec(None,None))
  DELETE_FILTER         = TypeInfo(bytes([26]),"!{0}s{0}s{1}s".format(_type_size,_ticket_size),("Type1","Type2","Ticket"),
                            Codec(lambda a: map(utf_enc,a),
                                  lambda a: map(utf_dec,a)))

class MessageClass(Enum):
  PUBLIC_MSG = bytes([0])
  PRIVATE_MSG = bytes([1])
  

class MessageStrategy:

  strategies = dict()

  fmt_h = "!1s1s"
  fmt_t = "!{}s".format(_hash_size)

  def __init__(self,msg_class,msg_type):
    self.msg_class = msg_class
    self.msg_type = msg_type
    self.arg_count = 0 if msg_type.value.args is None else len(msg_type.value.args)
    self.parms_info = msg_type.value.args
    self.fmt_b = self.msg_type.value.fmt
    MessageStrategy.strategies[(msg_class,msg_type)] = self

  @staticmethod
  def detect_class(msg_buf):
    if msg_buf[0:1] == MessageClass.PUBLIC_MSG.value:
      return MessageClass.PUBLIC_MSG
    elif msg_buf[0:1] == MessageClass.PRIVATE_MSG.value:
      return MessageClass.PRIVATE_MSG
    raise BadMessageError("Invalid message class")

  @staticmethod
  def detect_type(msg_buf):
    for msg_type in MessageType:
      if msg_buf[1:2] == msg_type.value.bc:
        return msg_type
    raise BadMessageError("Failed to detect message type")
      
  def build(self,args=None,stream=None,hmacf=None):
    if self.arg_count:
      assert len(args)==self.arg_count
    else:
      assert not args
    assert bool(stream) == bool(hmacf)
    assert self.msg_class != MessageClass.PRIVATE_MSG or (stream and hmacf)
    header_buf = struct.pack(MessageStrategy.fmt_h,self.msg_class.value,
                                self.msg_type.value.bc)
    if args:
      args = tuple(self.msg_type.value.codec.enc(args))
      body_buf = struct.pack(self.fmt_b,*args)
    else:
      body_buf = bytes([0])
    body_buf += bytes([0])*(_msg_size-(len(body_buf)+len(header_buf)+_hash_size))
    msg_buf = header_buf[1:2] + body_buf
    if self.msg_class == MessageClass.PRIVATE_MSG:
      msg_buf = stream.xor(msg_buf)
      msg_buf += struct.pack(MessageStrategy.fmt_t,hmacf(msg_buf))
    else:
      msg_buf += bytes([0])*_hash_size
    msg_buf = header_buf[0:1] + msg_buf
    assert len(msg_buf) == _msg_size
    return msg_buf

  @staticmethod
  def parse(msg_buf,stream=None,hmacf=None):
    assert msg_buf
    assert bool(stream) == bool(hmacf)
    assert len(msg_buf) == _msg_size
    msg_class = MessageStrategy.detect_class(msg_buf)
    if msg_class == MessageClass.PRIVATE_MSG:
      assert stream
      assert hmacf
      if compare_digest(hmacf(msg_buf[1:-_hash_size]),msg_buf[-_hash_size:]):
        msg_buf = msg_buf[0:1] + stream.xor(msg_buf[1:-_hash_size])
      else:
        raise BadMessageError("Message integrity check failure")
    msg_type = MessageStrategy.detect_type(msg_buf)
    if not (msg_class,msg_type) in strategies:
      raise BadMessageError("Bad msg_class,msg_type combination")
    fmt_b = msg_type.value.fmt
    msg_dict = dict()
    if fmt_b:
      contents = struct.unpack_from(fmt_b,msg_buf,2)
      contents = tuple(msg_type.value.codec.dec(contents))
      arg_count = len(msg_type.value.args)
      assert len(contents) == len(msg_type.value.args)
      for i in range(arg_count):
        entry_title = msg_type.value.args[i]
        value = contents[i]
        if entry_title in msg_dict.keys():
          try:
            msg_dict[entry_title].append(value)
          except AttributeError:
            msg_dict[entry_title] = [msg_dict[entry_title]]
            msg_dict[entry_title].append(value)
        else:
          msg_dict[entry_title] = value
    msg_dict["MessageClass"] = msg_class
    msg_dict["MessageType"] = msg_type
    return msg_dict
    
  def __repr__(self):
    str(self.__class__) + ": " + str(self.__dict__)

#Public messages
MessageStrategy(MessageClass.PUBLIC_MSG,MessageType.HELLO_SERVER)
MessageStrategy(MessageClass.PUBLIC_MSG,MessageType.HELLO_CLIENT)
MessageStrategy(MessageClass.PUBLIC_MSG,MessageType.DIE)
MessageStrategy(MessageClass.PUBLIC_MSG,MessageType.ERROR_SERVER)
MessageStrategy(MessageClass.PUBLIC_MSG,MessageType.AUTH_SUBJECT)

#Private messages
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.DIE)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.ERROR_SERVER)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.AUTH_SUBJECT)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.PULL_FILE)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.PUSH_FILE)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.XFER_FILE)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.OKAY)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.CONFIRM_AUTH)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.LIST_SUBJECT_CLIENT)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.LIST_SUBJECT_SERVER)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.LIST_OBJECT_CLIENT)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.LIST_OBJECT_SERVER)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.GIVE_TICKET_SUBJECT)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.TAKE_TICKET_SUBJECT)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.XFER_TICKET)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.MAKE_DIRECTORY)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.MAKE_SUBJECT)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.MAKE_FILTER)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.DELETE_FILTER)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.MAKE_LINK)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.CD)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.GET_CD)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.DELETE_PATH)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.CLEAR_LINKS)
MessageStrategy(MessageClass.PRIVATE_MSG,MessageType.DELETE_SUBJECT)

#Table of strategies for building messages
strategies = MessageStrategy.strategies

for msg_type in MessageType:
  assert bool(msg_type.value.fmt) == bool(msg_type.value.args)

#Notes
#
#Only subjects can have tickets (to objects)
#Must have access tickets to directory to list directory contents
#Objects are implicitly linked to all subjects that can view the directory
#Links between subjects are explicit and must exist for any transfer of tickets to occur
#Built messages are padded at the end with spaces, leading and trailing spaces must be ignored
#  by the client and the server. This hides the length of control messages
#Passwords are stored on the server for each client as the shared secret for key generation
#Neither links nor filters are bidirectional
#Super subjects exist that can create and destroy links and filters
#Some commands allow longer subject names than others
