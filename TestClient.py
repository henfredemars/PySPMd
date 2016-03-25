
import os
import random
import hashlib

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
  assert os.path.exists("test.bin")
  test_md5 = md5_file("test.bin")
  client = Client("localhost",5154)
  client.greetServer()
  client.authenticate("admin","password")
  print("Sending file...")
  client.sendFile("test.bin","test.bin")
  os.remove("test.bin")
  print("Getting file...")
  client.getFile("test.bin","test.bin")
  result_md5 = md5_file("test.bin")
  assert result_md5 == test_md5
  print("Signing out...")
  client.leaveServer()

def md5_file(fname):
  h = hashlib.md5()
  with open(fname, "rb") as f:
    for block in iter(lambda: f.read(4096), b""):
      h.update(block)
  return h.hexdigest()

if __name__=='__main__':
  print("I'm main!")
  main()
