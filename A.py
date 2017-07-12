#-*-coding:utf-8-*-
import random
import socket
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
import base64

# A、B共享口令字pw为 "123456"
pw = "123456"

# AES
class prpcrypt():
    def __init__(self, key):
        #这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.
        #目前AES-128足够用
        if len(key)<16:
            key=key+(16-len(key))*"\0"
        self.key = key[:16]
        self.mode = AES.MODE_CBC

    #加密函数，如果text不是16的倍数【加密文本text必须为16的倍数！】，那就补足为16的倍数
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, IV=self.key)
        length = 16
        count = len(text)
        add=count % length
        if add:
            text = text + ('\0' * (length-add))
        self.ciphertext = cryptor.encrypt(text)
        #因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        #所以这里统一把加密后的字符串用base64转化
        return base64.b64encode(self.ciphertext)

    #解密后，去掉补足的'\0'用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, IV=self.key)
        plain_text = cryptor.decrypt(base64.b64decode(text))
        return plain_text.rstrip('\0')

# RSA
# A随机生成一对新的、用于公钥加密方案E的公钥和私钥(pkA, skA)

# 伪随机数生成器
random_generator = Random.new().read
# rsa算法生成实例
rsa = RSA.generate(1024, random_generator)

# 公钥和私钥(pkA, skA)的生成
pkA = rsa.publickey().exportKey()
skA = rsa.exportKey()

address = ('127.0.0.1', 31500)
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(address)

print "pkA: " + pkA

# 发送自己的身份标识
socket.send('A')
data = socket.recv(1024)
if data != "yes":
    print "connect error"
    exit(-1)

#发送用pw加密的pkA的密文
pc = prpcrypt(pw)
e = pc.encrypt(pkA)
socket.send(e)

# 解密得Ks
data = socket.recv(1024)
pc = prpcrypt(pw)
Ks1 = pc.decrypt(data)
rsakey = RSA.importKey(skA)
cipher = Cipher_pkcs1_v1_5.new(rsakey)
Ks = cipher.decrypt(base64.b64decode(Ks1), random_generator)
print "Ks: " + Ks

# 随机生成NA并用Ks加密发送给B
a = [random.randint(0,9) for _ in range(10)]
NA = ''.join(str(i) for i in a)
print "NA: " + NA
pc = prpcrypt(Ks)
e = pc.encrypt(NA)
socket.send(e)
#print "E1(Ks,NA): " + e

# 解密后验证第一个分量
data = socket.recv(1024)
pc = prpcrypt(Ks)
N1_2 = pc.decrypt(data)
print 'N1_2: '+N1_2
if N1_2.find(NA) == 0:
    print "Authentication success"
else:
    print "Authentication faild"

# Ks加密N2发送给B
N2 = N1_2[len(NA):]
pc = prpcrypt(Ks)
e = pc.encrypt(N2)
socket.send(e)

while True:
    data = raw_input(">")
    if data == "quit":
        break
    socket.send(data)
    data = socket.recv(1024)
    print "Server say: " + data

socket.close()