from config import HOST, PORT, DB_PASSWORD, DB_HOST, DB_USER, LOG_PATH
from ModelUser import User
from ControllerUser import *

from logger import Logger

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
# import cgi
 


class HTTPHandler(BaseHTTPRequestHandler):
    __uController: UserController = UserController(
        hostname=DB_HOST,
        username=DB_USER,
        passwd=DB_PASSWORD
    )
    __logger: Logger = Logger(path_to_logfile=LOG_PATH)


    def __set_response(self, resp_code:int=200):
        self.send_response(resp_code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
    def __set_response_JSON(self, resp_code:int=200, dataJSON:dict={}):
        self.send_response(resp_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(bytes(json.dumps(dataJSON), 'utf-8'))

    # def __get_all_users(self) -> dict:

    def do_GET(self):
        message = {
            "status":"ok"
        }
        response_code = 200
        print("\n\n[GET]")
        if self.headers['content-type'] == "application/json":
            data_length:int = int(self.headers['content-length'])
            user_data: dict = dict(json.loads(self.rfile.read(data_length)))
            user_login:str = user_data["login"]
            user: User = self.__uController.get_user_by_login(user_login)
            
        
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

            if (self.__uController.check_user(user)):   
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
        
     

        
        
        
        


if __name__ == "__main__":
    
  server = HTTPServer((HOST, PORT), HTTPHandler)
  print(" >  Server now running...")
  server.serve_forever()
  server.server_close()
  print(" >  Server stopped!")

            

