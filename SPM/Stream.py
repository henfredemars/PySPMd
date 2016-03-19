
import hmac
import base64

#Stream

class RC4:

  def __init__(self,key):
    self.key = bytearray(key)
    assert len(key)==256
    self.s = [i for i in range(0,256)]
    j = 0
    for i in range(0,256):
      j = (j + self.s[i] + self.key[i % 256]) % 256
      self.s[i], self.s[j] = self.s[j], self.s[i]
    self.getBytes(2048)

  def getBytes(self,bs):
    i = 0
    j = 0
    stream = bytearray()
    for _ in range(bs):
      i = (i + 1) % 256
      j = (j + self.s[i]) % 256
      self.s[i], self.s[j] = self.s[j], self.s[i]
      stream.append(self.s[(self.s[i]+self.s[j]) % 256])
    return stream

  def xor(self,data):
    data = bytearray(data)
    stream = self.getBytes(len(data))
    return bytearray(map(lambda b: b[0]^b[1],zip(data,stream)))

  def encrypt(self,msg):
    msg = bytes(msg)
    return (base64.encode(self.xor(msg)).decode(encoding='ASCII',errors="strict") + "\n"
            ).encode('UTF-8',errors="strict")
  
  def decrypt(self,msg):
    msg = bytes(msg)
    return self.xor(base64.decode((msg.decode('UTF-8',errors="ignore").strip()).encode('ASCII')))

def make_hmacf(key):
  return (lambda msg: make_hmacf_single_use(key)(msg))

def make_hmacf_single_use(key):
  hmac_obj = hmac.new(bytes(key),msg=None,digestmod='sha1')
  return lambda msg: hmac_obj.update(msg) or hmac_obj.digest()
