import sqlite3
import shutil
import os

from SPM.Tickets import Ticket
from SPM.Subject import Subject
from SPM.Link import Link
from SPM.Filter import Filter
from SPM.Right import Right

#Database
#
#The goal of the database is to enforce consistency and provide uniform storage,
#  not to enforce the security model. Policy enforcement is delegated to the task handlers

class DatabaseError(RuntimeError):
  def __init__(self,msg):
    super().__init__(msg)

class Database:

  tables = ["create table if not exists subjects(subject text primary key, password text not null, type text not null, super integer not null)",
	    "create table if not exists links(subject1 text not null, subject2 text not null, primary key (subject1,subject2))",
	    "create table if not exists filters(type1 text not null, type2 text not null,ticket ticket not null, primary key (type1,type2,ticket))",
	    "create table if not exists rights(subject1 text not null, ticket ticket not null, target text not null, object integer not null, primary key (subject1,ticket,target,object))",
	    "create table if not exists objects(localpath text primary key, dir integer not null)"]

  #Setup automatic type conversions
  sqlite3.register_adapter("Ticket",Ticket.adapt_ticket)
  sqlite3.register_converter("Ticket",Ticket.convert_ticket)

  def __init__(self,db="./sys.db",root="./fileroot"):
    self.db = db
    self.root = root
    self.conn = sqlite3.connect(db,8,sqlite3.PARSE_DECLTYPES)
    self.conn.isolation_level = None
    self.c = self.conn.cursor()
    self.c.execute("begin transaction")
    [self.c.execute(s) for s in Database.tables]
    self.c.execute("end transaction")
    if not os.path.exists(self.root):
      os.mkdir(self.root)

  def __enter__(self):
    return self

  def insertSubject(self,name,password,stype,super=False):
    if not password or not name or not stype:
      raise DatabaseError("Name, password, and type are required")
    self.c.execute("begin transaction")
    self.c.execute("select subject from subjects where subject=?",(name,))
    if self.c.fetchone():
      self.c.execute("end transaction")
      raise DatabaseError("The subject already exists")
    self.c.execute("insert into subjects values(?,?,?,?)", (name,password,stype,super))
    self.c.execute("end transaction")

  def getSubject(self,name):
    if not name:
      raise DatabaseError("Cannot fetch subject without a name")
    self.c.execute("select * from subjects where subject=?",(name,))
    t = self.c.fetchone()
    if t:
      return Subject(*t)
    return None

  def getSubjectNames(self):
    subjects = []
    for subject in self.c.execute("select subject from subjects order by subject"):
      subjects.append(subject[0])
    return subjects
    
  def deleteSubject(self,name):
    if not name:
      raise DatabaseError("Cannot delete subject without a name")
    self.c.execute("begin transaction")
    self.c.execute("delete from subjects where subject=?",(name,))
    self.c.execute("delete from links where subject1=? or subject2=?",(name,))
    self.c.execute("delete from rights where subject=?",(name,))
    self.c.execute("end transaction")

  def clearLinks(self,name):
    if not name:
      raise DatabaseError("Cannot clear subject links without a name")
    self.c.execute("begin transaction")
    self.c.execute("delete from links where subject1=? or subject2=?",(name,))
    self.c.execute("end transaction")

  def insertLink(self,subject1,subject2):
    if not subject1 or not subject2:
      raise DatabaseError("Subject cannot be empty")
    if not self.getSubject(subject1) or not self.getSubject(subject2):
      raise DatabaseError("One of the subjects does not exist in the subjects table")
    if self.getLink(subject1,subject2):
      return #Link already exists
    self.c.execute("begin transaction")
    self.c.execute("insert into links values(?,?)",(subject1,subject2))
    self.c.execute("end transaction")

  def getLink(self,subject1,subject2):
    if not subject1 or not subject2:
      raise DatabaseError("Subject cannot be empty")
    self.c.execute("select subject1,subject2 from from links if subject1=? and subject2=?",
	(subject1,subject2))
    t = self.c.fetchone()
    if t:
      return Link(*t)
    return None

  def deleteLink(self,subject1,subject2):
    if not subject1 or not subject2:
      raise DatabaseError("Subject cannot be empty")
    self.c.execute("begin transaction")
    self.c.execute("delete from links where subject1=? and subject2=?",(subject1,subject2))
    self.c.execute("end transaction")

  def insertFilter(self,type1,type2,ticket):
    if not type1 or not type2:
      raise DatabaseError("Types cannot be empty")
    if not ticket:
      raise DatabaseError("No filter condition provided")
    try:
      ticket = Ticket.convert_ticket(ticket)
    except AssertionError:
      raise DatabaseError("Not a vaild ticket")
    if self.getFilter(type1,type2,ticket):
      return
    self.c.execute("begin transaction")
    self.c.execute("insert into filters values(?,?,?)",(type1,type2,ticket))
    self.c.execute("end transaction")

  def getFilter(self,type1,type2,ticket):
    if not type1 or not type2:
      raise DatabaseError("Types cannot be empty")
    if not ticket:
      raise DatabaseError("No filter condition provided")
    try:
      ticket = Ticket.convert_ticket(ticket)
    except AssertionError:
      raise DatabaseError("Not a vaild ticket")
    self.c.execute("select * from filters where type1=? and type2=? and ticket=?",
	(type1,type2,ticket))
    t = self.c.findone()
    if t:
      return Filter(*t)
    return None

  def deleteFilter(self,type1,type2,ticket):
    if not type1 or not type2:
      raise DatabaseError("Types cannot be empty")
    if not ticket:
      raise DatabaseError("No filter condition provided")
    try:
      ticket = Ticket.convert_ticket(ticket)
    except AssertionError:
      raise DatabaseError("Not a vaild ticket")
    self.c.execute("begin transaction")
    self.c.execute("delete from filters where type1=? and type2=? and ticket=?",
	(type1,type2,ticket))
    self.c.execute("end transaction")

  def insertRight(self,subject,ticket,target,isobject=False):
    if not subject:
      raise DatabaseError("Subject cannot be empty")
    if not target:
      raise DatabaseError("Target cannot be empty")
    if not ticket:
      raise DatabaseError("No ticket provided")
    if not self.getSubject(subject):
      raise DatabaseError("Subject must exist")
    if isobject:
      if not self.getObject(target):
        raise DatabaseError("Target object does not exist in database")
    else:
      if not self.getSubject(target):
        raise DatabaseError("Target subject does not exist in the database")
    try:
      ticket = Ticket.convert_ticket(ticket)
    except AssertionError:
      raise DatabaseError("Not a vaild ticket")
    if self.getRight(subject,ticket,target,isobject):
      return
    self.c.execute("begin transaction")
    self.c.execute("insert into rights values(?,?,?,?)",(subject,ticket,target,isobject))
    self.c.execute("end transaction")

  def getRight(self,subject,ticket,target,isobject=False):
    if not subject:
      raise DatabaseError("Subject cannot be empty")
    if not target:
      raise DatabaseError("Target cannot be empty")
    if not ticket:
      raise DatabaseError("No ticket provided")
    self.c.execute("select subject,ticket,target,object from rights where subject=? and ticket=? and target=? and isobject=?",
	(subject,ticket,target,isobject))
    t = self.c.fetchone()
    if t:
      return Right(*t)
    return None

  def deleteRight(self,subject,ticket,target,isobject=False):
    if not subject:
      raise DatabaseError("Subject cannot be empty")
    if not target:
      raise DatabaseError("Target cannot be empty")
    if not ticket:
      raise DatabaseError("No ticket provided")
    try:
      ticket = Ticket.convert_ticket(ticket)
    except AssertionError:
      raise DatabaseError("Not a vaild ticket")
    self.c.execute("begin transaction")
    self.c.execute("delete from rights where subject=? and ticket=? and target=? and object=?",
	(subject,ticket,target,isobject))
    self.c.execute("end transaction")

  def insertObject(self,localpath,isdir=False):
    if not localpath:
      raise DatabaseError("A path is required")
    if localpath[0] != "/":
      raise DatabaseError("The path is invalid")
    path_so_far = self.root
    for folder in localpath.split(os.sep):
      if folder and (not folder == os.path.basename(localpath)):
        path_so_far = os.path.join(path_so_far,folder)
        if not os.path.isdir(path_so_far):
          raise DatabaseError("A parent directory is missing from the filesystem")
    self.c.execute("begin transaction")
    self.c.execute("insert into objects values(?,?)",(localpath,isdir))
    self.c.execute("end transaction")

  def getObject(self,localpath):
    if not localpath:
      raise DatabaseError("A path is required")
    if localpath[0] != "/":
      raise DatabaseError("The path is invalid")
    self.c.execute("select localpath from objects where localpath=?",(localpath,))
    t = self.c.fetchone()
    if t:
      return t[0]
    return None

  def getObjectNames(self,cd):
    if not cd:
      raise DatabaseError("A current directory is required")
    if cd[0] != "/":
      raise DatabaseError("The path is invalid")
    cd_e = cd.replace("_","\\_").replace("%","\\%") + "%"
    objects = []
    for object in self.c.execute("select localpath from objects where localpath like ? escape ?",(cd_e,"\\")):
      if len(object[0].split(os.sep)) == len(cd.split(os.sep)):
        objects.append(object[0])
    return objects                                 

  def readObject(self,localpath):
    if not localpath:
      raise DatabaseError("A path to an object is required")
    if localpath[0] != "/":
      raise DatabaseError("The path is invalid")
    if not self.getObject(localpath):
      raise DatabaseError("The path is not in the database")
    realpath = os.path.join(self.root,localpath[1:])
    if not os.path.isfile(realpath):
      raise DatabaseError("Object does not exist for reading")
    return open(realpath,'rb')

  def writeObject(self,localpath):
    if not localpath:
      raise DatabaseError("A path to an object is required")
    if localpath[0] != "/":
      raise DatabaseError("The path is invalid")
    if not self.getObject(localpath):
      raise DatabaseError("The path is not in the database")
    realpath = os.path.join(self.root,localpath[1:])
    return open(realpath,'wb')

  def deleteObject(self,localpath):
    if not localpath:
      raise DatabaseError("A path to an object is required")
    if localpath[0] != "/":
      raise DatabaseError("The path is invalid")
    if not self.getObject(localpath):
      raise DatabaseError("The path is not in the database")
    realpath = os.path.join(self.root,localpath[1:])
    if os.path.isdir(realpath):
      shutil.rmtree(realpath)
    else:
      os.remove(realpath)
    self.c.execute("begin transaction")
    self.c.execute("delete from objects where localpath=?",(localpath,))
    self.c.execute("end transaction")

  def __exit__(self,exc_type,exc_value,traceback):
    self.close()

  def close(self):
    self.conn.close()
    
