from    Crypto.Hash             import  SHAKE256 
from    Crypto.Hash             import  SHA256
from    Crypto.Hash             import  SHA3_256
from    Crypto.Hash.SHA256      import  SHA256Hash
from    Crypto.Hash.SHA3_256    import  SHA3_256_Hash

def gen_salt() -> bytes:
  salt:bytes = None
  with open("/dev/urandom", 'br') as rf:
    salt = rf.read(2)
  return salt

def hash_passwd_SHAKE256(password:bytes) -> str:
  def set_fill(ch:str) -> str:
    if (len(ch) < 2):
      ch = '0' + ch
    return ch

  shake: SHAKE256_XOF = SHAKE256.new(password)

  data: list = [shake.read(1)[0] for _ in range( (256 // 8) )]
  res:str = ""
  for b in data:
    res += set_fill(hex(b)[2:])
  return res

def hash_passwd_SHA256(password:bytes) -> str:
  def set_fill(ch:str) -> str:
    if (len(ch) < 2):
      ch = '0' + ch
    return ch

  sha256: SHA256Hash = SHA256.new(password)
  return sha256.hexdigest()
  

def hash_passwd_SHA3_256(password:bytes) -> str:
  def set_fill(ch:str) -> str:
    if (len(ch) < 2):
      ch = '0' + ch
    return ch

  sha3_256: SHA3_256_Hash = SHA3_256.new(password)
  return sha3_256.hexdigest()

