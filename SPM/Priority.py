
import math

from enum import Enum
from time import time as time_sec
from time import sleep
from threading import Lock

time = lambda: math.ceil(time_sec()*1000)

class Priority(Enum):
  MIN = 800
  MAX = 0
  IDLE = 500
  HIGH = 0
  SPIN_TIME = 1
  PRECISION = 10

class PriorityQueue:

  def __init__(self):
    self.lock = Lock()
    self.q = []

  def put(self,priority,item):
    if priority > Priority.MIN.value:
      priority = Priority.MIN.value
    if priority < Priority.MAX.value:
      priority = Priority.MAX.value
    with self.lock:
      self.q.append([priority,priority,item])

  def get(self):
    self.lock.acquire()
    while not self.q:
      self.lock.release()
      sleep(Priority.SPIN_TIME.value)
      self.lock.acquire()
    min_p = float('inf')
    sel = None
    for item in self.q:
      if item[0] < min_p:
        min_p = item[0]
        sel = item
    self.q.remove(sel)
    self.lock.release()
    return sel

  def update(self,elapsed):
    with self.lock:
      for item in self.q:
        item[0] -= elapsed
        if item[0] < 0:
          item[0] = 0

