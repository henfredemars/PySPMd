
from SPM.Client import Client
from SPM.Database import Database

#Test of the server and client libraries

def main():
  db = Database()
  if not db.getSubject("admin"):
    db.insertSubject("admin","password",True)
  db.close()
  client = Client("localhost",5154)
  client.greetServer()
  client.authenticate("admin","password")
  client.leaveServer()

if __name__=='__main__':
  print("I'm main!")
  main()
