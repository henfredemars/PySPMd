
import os
import random
import readline
import subprocess
from cmd import Cmd

from SPM.Database import Database
from SPM.Client import Client

#An interactive command-line interface for 

INJECT_DEFAULT = True

class SpicyTerminal(Cmd):
  """Interactive remote terminal for the PySPMd"""

  def __init__(self):
    super().__init__()
    self.client = None
    self.userpath = os.path.expanduser("~")
    self.prompt_h = "(spicy-spm-client[%s]) "
    self.updatePrompt()
    self.intro = "Spicy PySPMd interpreter. Type 'help' for a list of commands."

  def updatePrompt(self):
    self.prompt = self.prompt_h % os.getcwd()
    self.prompt = self.prompt.replace(self.userpath,"~")

  def emptyline(self):
    """Discard empty line and return to the prompt"""
    pass

  def onecmd(self,s):
    """Catch and print exceptions without closing the interpreter"""
    try:
      return super().onecmd(s)
    except Exception as e:
      print(e)
      return False

  def postcmd(self,stop,line):
    """Update the prompt in case the working directory changes after each command"""
    self.updatePrompt()
    return stop

  def postloop(self):
    """Make sure to disconnect the client before quitting"""
    if self.client:
      self.client.close()

  def do_quit(self,line):
    """[quit] Quit the interpreter, closing any open connections"""
    return True

  def do_exit(self,line):
    """[exit] Same as quit"""
    return True

  def do_bye(self,line):
    """[bye] Same as quit"""
    return True

  def do_open(self,line):
    """[open server port] Open a new PySPMd connection"""
    args = line.split()
    if len(args) != 2:
      print("Incorrect number of arguments")
    else:
      if self.client:
        self.client.close()
      self.client = Client(args[0],int(args[1]))
      self.client.greetServer()
      print("Connection established.")

  def do_close(self,line):
    """[close] close all active connections"""
    if self.client:
      self.client.close()
      self.client = None
    print("All open connections have been closed")

  def do_auth(self,line):
    """[auth subject password] authenticate with the connected server"""
    args = line.split()
    if len(args) != 2:
      print("Incorrect number of arguments")
    elif not self.client or not self.client.connected:
      print("No connections available for the authentication")
    else:
      self.client.authenticate(args[0],args[1])

  def do_shell(self,line):
    """[!...] execute line using the default shell"""
    print(subprocess.run(line,shell=True,stdout=subprocess.PIPE).stdout.decode(encoding="UTF-8"))

  def do_lcd(self,line):
    """[lcd path] change the local working directory"""
    if not line:
      line = self.userpath
    os.chdir(line)

  def do_lls(self,line):
    """[lls path] list the contents of a local directory"""
    if not line:
      line = os.getcwd()
    [print(item) for item in os.listdir(line)]

  def do_lpwd(self,line):
    """[lpwd] print the current local working directory"""
    print(os.getcwd())

  def do_list_subjects(self,line):
    """[list_subjects] list all valid subjects on the server"""
    if not self.client or not self.client.connected:
      print("No active connection")
    else:
      subjects = self.client.listSubjects()
      print("Available Subjects:")
      [print(subject) for subject in subjects]

  def do_ls(self,line):
    """[ls] list objects in the working directory on the server"""
    if not self.client or not self.client.connected:
      print("No active connection")
    else:
      objects = self.client.listObjects()
      print("Available Objects:")
      [print(object) for object in objects]

  def do_cd(self,line):
    """[cd] change object directory on the server"""
    if not self.client or not self.client.connected:
      print("No active connection")
    elif not line:
      return
    else:
      self.client.cd(line)

  def do_pwd(self,line):
    """[pwd] print the current remote working directory"""
    if not self.client or not self.client.connected:
      print("No active connection")
    else:
      print(self.client.pwd())

  def do_get(self,remotename):
    """[get file] download a file from the security daemon"""
    if not self.client or not self.client.connected:
      print("No active connection")
    else:
      self.client.getFile(remotename,os.path.basename(remotename))

  def do_put(self,localname):
    """[put file] upload a file to the server"""
    if not self.client or not self.client.connected:
      print("No active connection")
    else:
      self.client.getFile(os.path.basename(remotename),localname)

  def do_lrm(self,file):
    """[lrm file] delete a single file from the local directory"""
    os.remove(file)

  def do_rm(self,file):
    """[rm file] delete a single file from the remote directory"""
    if not self.client or not self.client.connected:
      print("No active connection")
    else:
      self.client.deleteFile(file)
  
def main():
  SpicyTerminal().cmdloop()

def prep_sys():
  """Inject a default superuser and provide a test file (admin,admin,password)"""
  if not INJECT_DEFAULT:
    return
  with Database() as db:
    if not db.getSubject("admin"):
      db.insertSubject("admin","password","main",True)
  if os.path.exists("test.bin"):
    os.remove("test.bin")
  with open("test.bin","wb") as fd:
    [fd.write(bytearray(random.getrandbits(8) for _ in range(1024))) for _ in range(100)]
  assert os.path.exists("test.bin")

if __name__=='__main__':
  print("I'm main!")
  prep_sys()
  main()
