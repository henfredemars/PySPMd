import socket
from select import select

from SPM.Database import Database
from SPM.Util import log
from SPM.Events import ClientData
from SPM.Status import Status
import SPM.Events as EventServices

from collections import deque
from threading import Thread, Condition
from time import sleep

#Server

class Server():

  def __init__(self,bind,port):
    self.port = port
    self.bind = bind
    self.scopes_avail = Condition()
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.bind((bind,port))
    self.socket.listen(32)
    self.dq = deque()
    self.scopes = dict()
    self.worker = Thread(target = self.workerDispatch, daemon = True)

  def getScopesStatus(self,status):
    scopes = []
    for fileno in self.scopes:
      scope = self.scopes[fileno]
      if scope.status == status:
        scopes.append(scope)
    return scopes

  def reapDeadScopes(self):
    dead = []
    with self.scopes_avail:
      for fileno in self.scopes:
        scope = self.scopes[fileno]
        if scope.status == Status.DYING or scope.socket.fileno() < 0:
          dead.append(scope)
    if dead:
      for fileno in dead:
        del self.scopes[fileno]

  def blockOnBlockedScopes(self):
    blocked_send = self.getScopesStatus(Status.BLOCKED_SEND)
    blocked_recv = self.getScopesStatus(Status.BLOCKED_RECV)
    blocked_send_s = tuple(map(lambda s:s.socket,blocked_send))
    blocked_recv_s = tuple(map(lambda s:s.socket,blocked_recv))
    if not blocked_send_s and not blocked_recv_s:
      return
    _ = select(blocked_recv_s,blocked_send_s,[])

  def wakeUpBlockedScopes(self):
    blocked_send = self.getScopesStatus(Status.BLOCKED_SEND)
    blocked_recv = self.getScopesStatus(Status.BLOCKED_RECV)
    blocked_send_s = map(lambda s:s.socket,blocked_send)
    blocked_recv_s = map(lambda s:s.socket,blocked_recv)
    wake,rw,_ = select(blocked_recv_s,blocked_send_s,[],False)
    wake.extend(rw)
    wake = [self.scopes[socket.fileno()] for socket in wake]
    for scope in wake:
      scope.status = Status.RUN
      resume_func = scope.resume
      scope.resume = None
      resume_func()

  def workerDispatch(self):
    EventServices.db = Database()
    while True:
      try:
        task = None
        try:
          task = self.dq.popleft()
        except IndexError:
          with self.scopes_avail:
            while not self.scopes:
              self.scopes_avail.wait()
            self.reapDeadScopes()
            self.blockOnBlockedScopes()
            self.wakeUpBlockedScopes()
        else:
          task()
      except Exception as e:
        log("Caught (Otherwise) Fatal Exception: %s" % str(e))
        raise

  def mainloop(self):
    log("Dispatching worker...")
    self.worker.start()
    log("Entering main loop...")
    while True:
      (socket,addr) = self.socket.accept()
      scope = ClientData(socket)
      with self.scopes_avail:
        self.scopes[socket.fileno()] = scope
        self.scopes_avail.notify()
      self.dq.append(lambda: EventServices.Events.acceptClient(self.dq,scope))

