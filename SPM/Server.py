
import asyncio

import SPM.Protocol

from SPM.Database import Database
from SPM.Util import log

SPM.Protocol.db = Database()

#Server

class Server():

  def __init__(self,bind,port):
    self.port = port
    self.bind = bind
    self.loop = asyncio.get_event_loop()
    self.loop.run_until_complete(self.loop.create_server(
		lambda: SPM.Protocol.Protocol(self.loop),self.bind,self.port))

  def mainloop(self):
    log("Entering the event loop...")
    self.loop.run_forever()
