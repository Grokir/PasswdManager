
class User:
  # private fields
  __login:        str = None
  __passwd:       str = None
  __full_name:    str = None
  __position:     str = None
  __role:         str = None


  def __init__(
      self, 
      username:str="", 
      password:str="", 
      full_name:str="",
      position:str="",
      role:str="" 
  ):
    self.__login      = username
    self.__passwd     = password
    self.__full_name  = full_name
    self.__position   = position
    self.__role       = role

  # Getters

  def getLogin(self) -> str:
    return self.__login
  
  def getPasswd(self) -> str:
    return self.__passwd
  
  def getFullName(self) -> str:
    return self.__full_name
  
  def getPosition(self) -> str:
    return self.__position
  
  def getRole(self) -> str:
    return self.__role

  # Setters

  def setLogin(self, value: str) -> None:
    self.__login = value
  
  def setPasswd(self, value: str) -> None:
    self.__passwd = value
  
  def setFullName(self, value: str) -> None:
    self.__full_name = value
  
  def setPosition(self, value: str) -> None:
    self.__position = value
  
  def setRole(self, value: str) -> None:
    self.__role = value


  
  