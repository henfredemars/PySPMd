
from SPM.Client import Client

#Test of the server and client libraries

def main():
  client = Client("localhost",5154)

if __name__=='__main__':
  print("I'm main!")
  main()
