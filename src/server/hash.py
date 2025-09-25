from    Crypto.Hash             import  SHAKE256 
from    Crypto.Hash.SHAKE256    import  SHAKE256_XOF

def gen_salt() -> str:
  salt:str = None
  with open("/dev/urandom", 'r') as rf:
    salt = rf.read(4).encode('utf-8')
  return salt

def hash_passwd(password:str) -> str:
  def set_fill(ch:str) -> str:
    if (len(ch) < 2):
      ch = '0' + ch
    return ch

  shake: SHAKE256_XOF = SHAKE256.new( 
    bytes(password + gen_salt(), encoding="utf-8") 
  )

  data: list = [shake.read(1)[0] for _ in range( (256 // 8) )]
  res:str = ""
  for b in data:
    res += set_fill(hex(b)[2:])
  return res
