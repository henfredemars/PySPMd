import socket

from SPM.Events import Events
from SPM.Util import log

from collections import deque
from threading import Thread
from time import sleep

#Server

class Server():

  def __init__(self,bind,port,idlepoll=700):
    self.port = port
    self.bind = bind
    self.idlepoll = idlepoll
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.bind((bind,port))
    self.socket.listen(32)
    self.dq = deque()
    self.worker = Thread(target = self.workerDispatch, daemon = True)

  def workerDispatch(self):
    while True:
      task = None
      try:
        task = self.dq.popleft()
      except IndexError:
        sleep(self.idlepoll/1000)
        continue
      try:
        task()
      except IOError as e:
        log("IOError: %s" % str(e))
        continue

  def mainloop(self):
    log("Dispatching worker...")
    self.worker.start()
    log("Entering main loop...")
    while True:
      (socket,addr) = self.socket.accept()
      self.dq.append(lambda: Events.acceptClient(self.dq,socket))

