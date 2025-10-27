from config import HOST, PORT, DB_PASSWORD, DB_HOST, DB_USER, LOG_PATH
from Model.User import User
from Controller.UserController import *
import hash

from logger import Logger

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
# import cgi



class HTTPHandler(BaseHTTPRequestHandler):
    __uController: UserController = UserController(
        hostname = DB_HOST,
        username = DB_USER,
        passwd   = DB_PASSWORD
    )
    __logger: Logger = Logger(path_to_logfile=LOG_PATH)
    __pass_type: str = "open"

    def __check_password(self, user: User) -> bool:
        bits: int = 16
        # src_passwd: str = user.getPasswd()
        tmp_user: User = self.__uController.get_user_by_login(user.getLogin())

        if tmp_user.getLogin() != "":
            if tmp_user.getPasswd() == user.getPasswd():
                return True
            
            for i in range(2**bits):
                bit_str:    str     = f"{i:0{bits}b}"
                byte_str:   bytes   = int(bit_str, 2).to_bytes((bits // 8), 'big')
                tmp_passwd: bytes   = bytes(user.getPasswd(), encoding="utf-8") + byte_str
                
                if hash.hash_passwd_SHAKE256(tmp_passwd) == tmp_user.getPasswd():
                    return True

                # user.setPasswd(hash.hash_passwd(tmp_passwd))
            
                # if self.__uController.check_user(user):
                #     return True

        return False
    
    def __get_password(self, login:str, password:str) -> tuple[str, None]:
        bits: int = 16
        user: User = User()
        user.setLogin(login)
        
        for i in range(2**bits):
            bit_str = f"{i:0{bits}b}"
            byte_str = int(bit_str, 2).to_bytes((bits // 8), 'big')
            tmp_passwd = bytes(password, encoding="utf-8") + byte_str
            hash_password = hash.hash_passwd_SHAKE256(tmp_passwd)
            user.setPasswd(hash_password)
           
            if self.__uController.check_user(user):
                return hash_password

        return None
    
    def __hash_password(self, src_password: str) -> str:
        modified_passwd: str     = src_password

        match self.__pass_type:
            case "open":
                modified_passwd = src_password
            case "shake256":
                salt:            bytes  = hash.gen_salt()
                salted_passwd:   bytes  = bytes(src_password, encoding="utf-8") + salt
                modified_passwd         = hash.hash_passwd_SHAKE256(salted_passwd)
            case "sha2-256":
                salt:            bytes  = hash.gen_salt()
                salted_passwd:   bytes  = bytes(src_password, encoding="utf-8") + salt
                modified_passwd         = hash.hash_passwd_SHA256(salted_passwd)

            case "sha3-256":
                salt:            bytes  = hash.gen_salt()
                salted_passwd:   bytes  = bytes(src_password, encoding="utf-8") + salt
                modified_passwd         = hash.hash_passwd_SHA3_256(salted_passwd)
                
        return modified_passwd
    

    def __set_response(self, resp_code:int=200):
        self.send_response(resp_code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
    def __set_response_JSON(self, resp_code:int=200, dataJSON:dict={}):
        self.send_response(resp_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(bytes(json.dumps(dataJSON), 'utf-8'))
    
    def __get_data_curr_user(self) -> tuple[dict, str]:
        data_length:int  = int(self.headers['content-length'])
        user_data:  dict = dict(json.loads(self.rfile.read(data_length)))
        user_login: str  = user_data["login"]
        user:       User = self.__uController.get_user_by_login(user_login)
        user_json:  dict = {
            "login":     str(user.getLogin()),
            "full_name": str(user.getFullName()),
            "position":  str(user.getPosition()),
            "role":      str(user.getRole())
        }
        return user_json, user.getLogin()
    
    def __get_data_all_users(self) -> tuple[list, str]:
        data_length:int  = int(self.headers['content-length'])
        user_data:  dict = dict(json.loads(self.rfile.read(data_length)))
        user_login: str  = user_data["login"]
        user:       User = self.__uController.get_user_by_login(user_login)
        user_json:  list = []

        if user.getRole() == user_data["role"]:
            if user.getRole() in ["admin", "super_user"]:
                for u in self.__uController.get_all_users():
                    user_json.append(
                        {
                            "login":     str(u.getLogin()),
                            "full_name": str(u.getFullName()),
                            "position":  str(u.getPosition()),
                            "role":      str(u.getRole())
                        }
                    )                   

        return user_json, user.getLogin()

    def __get_logs(self) -> tuple[list, str]:
        data_length:int  = int(self.headers['content-length'])
        user_data:  dict = dict(json.loads(self.rfile.read(data_length)))
        user_login: str  = user_data["login"]
        user:       User = self.__uController.get_user_by_login(user_login)
        log_json:   list = []

        if user.getRole() == user_data["role"]:
            if user.getRole() == "admin":
                with open(self.__logger.get_path(), 'r') as rf:
                    log_json = rf.readlines()

        return log_json, user.getLogin()
    

    def do_GET(self):
        message = {
            "status": "ok"
        }
        response_code = 200
        print(f"\n\n[GET {self.path}]")
        if self.headers['content-type'] == "application/json":
            resp_json = ""
            login_by_request = ""
            if self.path in ["/", "/all_users"]:
                if self.path == "/all_users":
                    resp_json, login_by_request = self.__get_data_all_users()
                    self.__logger.send(f"User from {self.client_address[0]}:{self.client_address[1]} get all users data")
                else:
                    resp_json, login_by_request = self.__get_data_curr_user()
                    self.__logger.send(f"User from {self.client_address[0]}:{self.client_address[1]} get user data by login '{login_by_request}'")
                message["user_data"] = json.dumps(resp_json)
                
            elif self.path == "/logs":
                resp_json, login_by_request = self.__get_logs()
                message["logs"] = json.dumps(resp_json)
                self.__logger.send(f"User from {self.client_address[0]}:{self.client_address[1]} get logs by login '{login_by_request}'")
            
        else:
            message = {
                "status":"error",
                "message":"bad format of input data"
            }
            response_code = 400
            self.__logger.send(f"An uncorrected POST request was received from {self.client_address[0]}:{self.client_address[1]}")
          
        self.__set_response_JSON(response_code, message)


    def do_POST(self):
        message = {}
        response_code = 200
        print("\n\n[POST]")
        if self.headers['content-type'] == "application/json":
            data_length:int = int(self.headers['content-length'])
            user_data: dict = dict(json.loads(self.rfile.read(data_length)))
            user: User = User(
                username=user_data["login"],
                password=user_data["password"]
            )
            self.__logger.send(f"User from {self.client_address[0]}:{self.client_address[1]} try connect with creds '{user.getLogin()}:{user.getPasswd()}'")

            if (self.__check_password(user)):
                message = {
                    "status":"ok"
                }
                self.__logger.send(f"Connection SUCCESS")
            else:
                message = {
                    "status":"error",
                    "message":"incorrect login or password"
                }
                response_code = 400
                self.__logger.send(f"Connection FAIL: incorrect login or password")
        else:
            message = {
                "status":"error",
                "message":"bad format of input data"
            }
            response_code = 400
            self.__logger.send(f"An uncorrected POST request was received from {self.client_address[0]}:{self.client_address[1]}")
            
        self.__set_response_JSON(response_code, message)
        
    def do_PATCH(self):
        message = {}
        response_code = 200
        print("\n\n[PATCH]")        

        # /chg_type_pass

        if self.headers['content-type'] == "application/json":
            data_length:int = int(self.headers['content-length'])
            json_data: dict = dict(json.loads(self.rfile.read(data_length)))
            

            user: User = User(
                username=json_data["login"],
                password=json_data["password"]
            )

            self.__logger.send(f"User from {self.client_address[0]}:{self.client_address[1]} with creds '{user.getLogin()}:{user.getPasswd()}' try UPDATE password")

            if (self.__check_password(user)):
                self.__logger.send(f"User verify SUCCESS")
                
                user = self.__uController.get_user_by_login(user.getLogin())
                
                if self.path in ["/", "/chg_type_pass"]:
                    if self.path == "/chg_type_pass":
                        if user.getRole() == "admin":
                            self.__pass_type = json_data["pass_type"]
                            message = {
                                "status":"ok"
                            }
                            self.__logger.send(
                                f"User with login '{user.getLogin()}' successful update password secure type to '{self.__pass_type}'"
                            )
                        else:
                            message = {
                                "status":"error",
                                "message":"access denied to update data"
                            }
                            response_code = 400
                            self.__logger.send(f"Update FAIL: access denied to update data")
                    else:
                        upd_data: dict = json_data["upd_data"]
                        if user.getRole() == "admin" or user.getLogin() == upd_data["login"]:
                            if self.__uController.update_password(
                                upd_data["login"],
                                self.__hash_password( upd_data["new_password"] )
                            ):
                                message = {
                                    "status":"ok"
                                }

                                self.__logger.send(
                                    f"User with login '{user.getLogin()}' successful update password for '{upd_data["login"]}' to '{upd_data["new_password"]}'"
                                )
                            else:
                                message = {
                                    "status":"error",
                                    "message":"update password is fail"
                                }
                                self.__logger.send(
                                    f"User with login '{user.getLogin()}' failure update password for '{upd_data["login"]}' from '{upd_data["old_password"]}' to '{upd_data["new_password"]}'"
                                )
                        else:
                            message = {
                                "status":"error",
                                "message":"access denied to update data"
                            }
                            response_code = 400
                            self.__logger.send(f"Update FAIL: access denied to update data")

            else:
                message = {
                    "status":"error",
                    "message":"incorrect login or password"
                }
                response_code = 400
                self.__logger.send(f"Verify FAIL: incorrect login or password")
            
        else:
            message = {
                "status":"error",
                "message":"bad format of input data"
            }
            response_code = 400
            self.__logger.send(f"An uncorrected POST request was received from {self.client_address[0]}:{self.client_address[1]}")
            
        self.__set_response_JSON(response_code, message)


    def do_PUT(self):
        message = {}
        response_code = 200
        print("\n\n[PUT]")
        if self.headers['content-type'] == "application/json":
            data_length:int = int(self.headers['content-length'])
            json_data: dict = dict(json.loads(self.rfile.read(data_length)))
            add_data:  dict = json_data["add_data"]

            user: User = User(
                username=json_data["login"],
                password=json_data["password"]
            )

            self.__logger.send(f"User from {self.client_address[0]}:{self.client_address[1]} with creds '{user.getLogin()}:{user.getPasswd()}' try ADD new user")

            if (self.__check_password(user)):
                self.__logger.send(f"User verify SUCCESS")

                user = self.__uController.get_user_by_login(user.getLogin())
                if user.getRole() == "admin":
                    hash_password: str = self.__hash_password(add_data["password"])
                    add_user: User = User(
                        username    =   add_data["login"],
                        password    =   hash_password,
                        full_name   =   add_data["full_name"],
                        position    =   add_data["position"],
                        role        =   add_data["role"]
                    )
                    if self.__uController.add_user(add_user) :
                        message = {
                            "status":"ok"
                        }

                        self.__logger.send(
                            f"User with login '{user.getLogin()}' successful add new user with login '{add_user.getLogin()}' and role '{add_user.getRole()}'"
                        )
                    else:
                        message = {
                            "status":"error",
                            "message":"add new user is fail"
                        }
                        self.__logger.send(
                            f"User with login '{user.getLogin()}' failure add new user with login '{add_user.getLogin()}' and role '{add_user.getRole()}'"
                        )
                else:
                    message = {
                        "status":"error",
                        "message":"access denied to add new user"
                    }
                    response_code = 400
                    self.__logger.send("ADD new user FAIL: access denied to add new user")

            else:
                message = {
                    "status":"error",
                    "message":"incorrect login or password"
                }
                response_code = 400
                self.__logger.send(f"Verify FAIL: incorrect login or password")
            
        else:
            message = {
                "status":"error",
                "message":"bad format of input data"
            }
            response_code = 400
            self.__logger.send(f"An uncorrected POST request was received from {self.client_address[0]}:{self.client_address[1]}")
            
        self.__set_response_JSON(response_code, message)


    def do_DELETE(self):
        message = {}
        response_code = 200
        print("\n\n[DELETE]")
        if self.headers['content-type'] == "application/json":
            data_length:int = int(self.headers['content-length'])
            json_data: dict = dict(json.loads(self.rfile.read(data_length)))
            del_data:  dict = json_data["del_data"]

            user: User = User(
                username=json_data["login"],
                password=json_data["password"]
            )

            self.__logger.send(f"User from {self.client_address[0]}:{self.client_address[1]} with creds '{user.getLogin()}:{user.getPasswd()}' try DELETE user")

            if (self.__check_password(user)):
                self.__logger.send(f"User verify SUCCESS")

                user = self.__uController.get_user_by_login(user.getLogin())
                if user.getRole() == "admin":
  
                    if self.__uController.del_user(del_data["login"]):
                        message = {
                            "status":"ok"
                        }

                        self.__logger.send(
                            f"User with login '{user.getLogin()}' successful delete user with login '{del_data["login"]}'"
                        )
                    else:
                        message = {
                            "status":"error",
                            "message":"add new user is fail"
                        }
                        self.__logger.send(
                            f"User with login '{user.getLogin()}' failure delete user with login '{del_data["login"]}'"
                        )
                else:
                    message = {
                        "status":"error",
                        "message":"access denied to delete user"
                    }
                    response_code = 400
                    self.__logger.send("DELETE user FAIL: access denied to delete user")

            else:
                message = {
                    "status":"error",
                    "message":"incorrect login or password"
                }
                response_code = 400
                self.__logger.send(f"Verify FAIL: incorrect login or password")
            
        else:
            message = {
                "status":"error",
                "message":"bad format of input data"
            }
            response_code = 400
            self.__logger.send(f"An uncorrected POST request was received from {self.client_address[0]}:{self.client_address[1]}")
            
        self.__set_response_JSON(response_code, message)
        

def run() -> None:     
    server = HTTPServer((HOST, PORT), HTTPHandler)
    server.serve_forever()
    server.server_close()
