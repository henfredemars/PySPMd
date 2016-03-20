import socket

from SPM.Database import Database
from SPM.Util import log
import SPM.Events as EventServices
from SPM.Priority import Priority
from SPM.Priority import PriorityQueue 

from threading import Thread
from time import sleep, time

#Server

class Server():

  def __init__(self,bind,port):
    self.port = port
    self.bind = bind
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.bind((bind,port))
    self.socket.listen(32)
    self.pq = PriorityQueue()
    self.last_time = time()
    self.worker = Thread(target = self.workerDispatch, daemon = True)

  def workerDispatch(self):
    EventServices.db = Database()
    while True:
      cur_pri,init_pri,task = self.pq.get()
      try:
        sleep(cur_pri/1000)
        task(init_pri)
        cur_time = time()
        self.pq.update(1000*(cur_time-self.last_time))
        self.last_time = cur_time
      except IOError as e:
        log("IOError: %s" % str(e))
        continue

  def mainloop(self):
    log("Dispatching worker...")
    self.worker.start()
    self.pq.put(Priority.IDLE.value,lambda i: EventServices.Events.idle(i,self.pq))
    log("Entering main loop...")
    while True:
      (socket,addr) = self.socket.accept()
      self.pq.put(Priority.HIGH.value,lambda i: EventServices.Events.acceptClient(i,self.pq,socket))

