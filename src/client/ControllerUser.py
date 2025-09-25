from ModelUser import User

import mysql.connector



class UserController:
  __user = None
  __connect = None


  def __init__(
      self,
      hostname="127.0.0.1",
      username="root",
      passwd=""
  ):
    try:
      con = mysql.connector.connect(
        host=hostname
        user=username,
        password=passwd,
        database="db_passwd_manager"
      )
      print("Connection successful!")

      self.__connect = con
    except mysql.connector.Error as err:
      print(f"Error connecting to MySQL: {err}")
      return None

  def __exec_query(self, query:str) -> bool:
    try:
      cur = self.__connect.cursor()
      cur.execute(query)
      result = cur.fetchall()
      print(f"Query result ({len(result)} arrows):")
      for x in result:
        print(x)
        
      return True
    except mysql.connector.Error as err:
      return False
    

  def set_user(self, user: User) -> None:
    self.__user = user

  def update_password(
      self,  
      login: str,
      old_password: str,
      new_password: str
  ) -> bool:
    
    upd_query: str = f"""
    UPDATE db_passwd_manager.credentials AS cred
    SET cred.passwd = {new_password}
    WHERE cred.login  = {login}
    AND   cred.passwd = {old_password}
    """

    return self.__exec_query(upd_query)
    
  def add_user(self, user: User) -> bool:
    insert_query: str = f"""
    INSERT INTO db_passwd_manager.credentials 
    (login, passwd) VALUE ("{user.getLogin()}", "{user.getPasswd()}")
    """

    return self.__exec_query(insert_query)
  
  def add_user(self, user: User) -> bool:
  insert_query: str = f"""
  INSERT INTO db_passwd_manager.credentials 
  (login, passwd) VALUE ("{user.getLogin()}", "{user.getPasswd()}")
  """

  return self.__exec_query(insert_query)