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


    def __check_password(self, user: User) -> bool:
        bits: int = 16
        
        for i in range(2**bits):
            bit_str = f"{i:0{bits}b}"
            byte_str = int(bit_str, 2).to_bytes((bits // 8), 'big')
            tmp_passwd = bytes(user.getPasswd(), encoding="utf-8") + byte_str
            user.setPasswd(hash.hash_passwd(tmp_passwd))
           
            if self.__uController.check_user(user):
                return True

        return False


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
            for u in self.__uController.get_all_users():
                if user.getRole() == "super_user":
                    user_json.append(
                        {
                            "login":     str(u.getLogin()),
                            "full_name": str(u.getFullName()),
                            "position":  str(u.getPosition())
                        }
                    )
                elif user.getRole() == "admin":
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
                else:
                    resp_json, login_by_request = self.__get_data_curr_user()
                message["user_data"] = json.dumps(resp_json)
            elif self.path == "/logs":
                resp_json, login_by_request = self.__get_logs()
                message["logs"] = json.dumps(resp_json)
            
            self.__logger.send(f"User from {self.client_address[0]}:{self.client_address[1]} get user_data by login '{login_by_request}'")
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
        
    
        

def run() -> None:     
    server = HTTPServer((HOST, PORT), HTTPHandler)
    server.serve_forever()
    server.server_close()
