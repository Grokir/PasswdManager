from sys import path as sys_path
sys_path.append("../Model")

from Model.User import User

import mysql.connector



class UserController:
  __connect = None


  def __init__(self, hostname:str="127.0.0.1", username:str="root", passwd:str=""):
    con = mysql.connector.connect(
      host=hostname,
      user=username,
      password=passwd,
      database="db_passwd_manager"
    )
    print("Connection successful!")

    self.__connect = con


  def __exec_query(self, query:str) -> list:
    try:
      cur: MySQLCursorAbstract = self.__connect.cursor()
      cur.execute(query)
      result:list = cur.fetchall()

      return result
    except mysql.connector.Error as err:
      print(f"Query error: {err}")
      return None
    

  def get_user_by_login(self, login:str) -> tuple[User, None]:
    user: User = User()
    query:str = f"""
    SELECT 
          cred.login, 
          cred.passwd, 
          ud.full_name,
          ud.position,
          ur.role
    FROM `credentials` AS cred
    JOIN `user_data` AS ud
    ON ud.login = cred.login
    JOIN `user_roles` AS ur
    ON ur.login = cred.login
    WHERE cred.login = "{login}"
    """

    result = self.__exec_query(query)

    if (len(result) > 0):
      user.setLogin     (result[0][0])
      user.setPasswd    (result[0][1])
      user.setFullName  (result[0][2])
      user.setPosition  (result[0][3])
      user.setRole      (result[0][4])

    return user


  def update_password(
      self,  
      login: str,
      old_password: str,
      new_password: str
  ) -> bool:
    
    upd_query: str = f"""
    UPDATE `credentials` AS cred
    SET cred.passwd = "{new_password}"
    WHERE cred.login  = "{login}"
    AND   cred.passwd = "{old_password}"
    """

    return ( self.__exec_query(upd_query) is not None)
    
  def add_user(self, user: User) -> bool:
    insert_query: str = f"""
    SELECT `ADD_NEW_USER`(
      "{user.getLogin()}", 
      "{user.getPasswd()}",
      "{user.getFullName()}",
      "{user.getPosition()}",
      "{user.getRole()}"
    );"""
    return ( self.__exec_query(insert_query) is not None)
  
  def check_user(self, user: User) -> bool:
    query:str = f"""
    SELECT cred.login 
    FROM `credentials` AS cred
    WHERE cred.login = "{user.getLogin()}"
    AND cred.passwd  = "{user.getPasswd()}";
    """

    return ( self.__exec_query(query) is not None ) 
    # return ( len(result) > 0 )
        
  def get_all_users(self) -> list:
    query:str = f"""
    SELECT login
    FROM `credentials`
    """
    user_list: list = []
    result = self.__exec_query(query)
    if (result is not None):
      user_list = [ self.get_user_by_login(result[i][0]) for i in range(len(result)) ]

    return user_list