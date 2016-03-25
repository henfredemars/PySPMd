
import os
import shutil

from SPM.Server import Server

#Test of the server and client libraries

def main():
  if os.path.exists("fileroot"):
    shutil.rmtree("fileroot")
  if os.path.exists("test.bin"):
    os.remove("test.bin")
  if os.path.exists("sys.db"):
    os.remove("sys.db")
  server = Server("localhost",5154)
  server.mainloop()

if __name__=='__main__':
  print("I'm main!")
  main()
