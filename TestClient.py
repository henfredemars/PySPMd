
import os
import random

from SPM.Client import Client
from SPM.Database import Database

#Test of the server and client libraries

def main():
  with Database() as db:
    if not db.getSubject("admin"):
      db.insertSubject("admin","password",True)
  if os.path.exists("test.bin"):
    os.remove("test.bin")
  with open("test.bin","wb") as fd:
    [fd.write(bytearray(random.getrandbits(8) for _ in range(1024))) for _ in range(100)]
  client = Client("localhost",5154)
  client.greetServer()
  client.authenticate("admin","password")
  #client.sendfile("test.bin","test.bin")
  client.leaveServer()

if __name__=='__main__':
  print("I'm main!")
  main()
