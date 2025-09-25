
class User:
  # private fields
  __id:          int = None
  __login:       str = ""
  __passwd: str = ""

  def __init__(self, id:int=0, username:str="", password:str=""):
    self.__id     = id
    self.__login  = username
    self.__passwd = password

  def getLogin(self) -> str:
    return self.__login
  
  def getPasswd(self) -> str:
    return self.__passwd
  
  def getCreds(self) -> str, str:
    """ return pair of <login:hash_password>"""
    return self.__login, self.__passwd
  