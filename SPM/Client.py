import socket

from . import __version__

from SPM.Util import log
from SPM.Messages import MessageStrategy

strategies = MessageStrategy.strategies

#Server

class Client():

  def __init__(self,addr,port):
    self.port = port
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.connect((addr,port))
    self.buf = []
    self.greetServer()

  def greetServer(self):
    self.socket.sendall(strategies["HELLO_CLIENT"].build([__version__]))
    self.buf.append(self.socket.recv(4096))
    print(self.buf)

  def close(self):
    self.socket.close()
