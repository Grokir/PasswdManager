import requests
# from requests import Response
import json
from config import HOST, PORT


class Receiver:

  def POST(self, dataJSON:dict) -> str:
    resp: requests.Response = requests.post(f"http://{HOST}:{PORT}/", json=dataJSON)
    res:dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return res["status"]
    
  def GET(self, dataJSON:dict) -> tuple[str, dict]:
    resp: requests.Response = requests.get(f"http://{HOST}:{PORT}/", json=dataJSON)
    res:dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return json.loads(res["user_data"])
  
  def GET_all_users(self, dataJSON:dict) -> tuple[str, list]:
    resp: requests.Response = requests.get(f"http://{HOST}:{PORT}/all_users", json=dataJSON)
    res:dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return json.loads(res["user_data"])
  
  def GET_logs(self, dataJSON:dict) -> tuple[str, list]:
    resp: requests.Response = requests.get(f"http://{HOST}:{PORT}/logs", json=dataJSON)
    res:dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return json.loads(res["logs"])


