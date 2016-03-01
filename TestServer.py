
from SPM.Server import Server

#Test of the server and client libraries

def main():
  server = Server("localhost",5154)
  server.mainloop()

if __name__=='__main__':
  print("I'm main!")
  main()
