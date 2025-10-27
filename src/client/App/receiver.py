from sys import path as sys_path
sys_path.append("../App")


import requests
import json
from App.config import HOST, PORT


class Receiver:

  def login(self, dataJSON:dict) -> str:
    resp: requests.Response = requests.post(f"http://{HOST}:{PORT}/", json=dataJSON)
    res:dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return res["status"]
    
  def get_current_user(self, dataJSON:dict) -> tuple[str, dict]:
    resp: requests.Response = requests.get(f"http://{HOST}:{PORT}/", json=dataJSON)
    res:dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return json.loads(res["user_data"])
  
  def get_all_users(self, dataJSON:dict) -> tuple[str, list]:
    resp: requests.Response = requests.get(f"http://{HOST}:{PORT}/all_users", json=dataJSON)
    res:dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return json.loads(res["user_data"])
  
  def get_logs(self, dataJSON:dict) -> tuple[str, list]:
    resp: requests.Response = requests.get(f"http://{HOST}:{PORT}/logs", json=dataJSON)
    res:dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return json.loads(res["logs"])
  
  def change_password(self, dataJSON:dict) -> str:
    resp: requests.Response = requests.patch(f"http://{HOST}:{PORT}/", json=dataJSON)
    res:  dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return res["status"]
  
  def add_user(self, dataJSON:dict) -> str:
    resp: requests.Response = requests.put(f"http://{HOST}:{PORT}/", json=dataJSON)
    res:  dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return res["status"]
  
  def del_user(self, dataJSON:dict) -> str:
    resp: requests.Response = requests.delete(f"http://{HOST}:{PORT}/", json=dataJSON)
    res:  dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return res["status"]
  
  def change_password_secure(self, dataJSON:dict) -> str:
    resp: requests.Response = requests.patch(f"http://{HOST}:{PORT}/chg_type_pass", json=dataJSON)
    res:  dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return res["status"]


