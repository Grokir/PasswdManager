import requests
from config import HOST, PORT


class Receiver:

  def POST(self, dataJSON:dict) -> str:
    resp: Response = requests.post(f"http://{HOST}:{PORT}/", json=dataJSON)
    res:dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return res["status"]
    
  def GET(self, dataJSON:dict):
    resp: Response = requests.get(f"http://{HOST}:{PORT}/", json=dataJSON)
    res:dict = resp.json()
    
    if res["status"] == "error":
      return res["message"]
    
    return res["user_data"]


