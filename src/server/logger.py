from datetime import datetime


class Logger:
  __timer: datetime = None
  __logfile: str  = "passwd_manager.log"

  def __init__(self, path_to_logfile:str = "/var/log/")->None:
    self.__timer = datetime
    self.__logfile = path_to_logfile + self.__logfile
  
  def send(self, message:str) -> None:
    with open(self.__logfile, 'a') as lf:
      lf.write(f"[{self.__timer.now()}] '{message}'\n")