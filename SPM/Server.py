
import asyncio

import SPM.Protocol

from SPM.Database import Database
from SPM.Util import log

#Server

class Server():

  def __init__(self,bind,port):
    if not SPM.Protocol.db:
      SPM.Protocol.db = Database()
    self.port = port
    self.bind = bind
    self.loop = asyncio.get_event_loop()
    self.server = self.loop.run_until_complete(self.loop.create_server(
		lambda: SPM.Protocol.Protocol(self.loop),self.bind,self.port))

  def mainloop(self):
    log("Entering the event loop...")
    try:
      self.loop.run_forever()
    finally:
      self.server.close()
      self.loop.run_until_complete(self.server.wait_closed())
      self.loop.close()

