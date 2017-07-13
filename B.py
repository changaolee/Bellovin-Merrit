# -*-coding:utf-8-*-
import os
import random
import socket
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
import base64
import threading

# A、B共享口令字pw为 "123456"
from Crypto.PublicKey import RSA

dict = {}
dict["A"] = "123456"
dict["B"] = "qweasd"

# AES
class prpcrypt():
    def __init__(self, key):
        # 这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.
        # 目前AES-128足够用
        if len(key) < 16:
            key = key + (16 - len(key)) * "\0"
        self.key = key[:16]
        self.mode = AES.MODE_CBC

    # 加密函数，如果text不是16的倍数【加密文本text必须为16的倍数！】，那就补足为16的倍数
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, IV=self.key)
        length = 16
        count = len(text)
        add = count % length
        if add:
            text = text + ('\0' * (length - add))
        self.ciphertext = cryptor.encrypt(text)
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串用base64转化
        return base64.b64encode(self.ciphertext)

    # 解密后，去掉补足的'\0'用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, IV=self.key)
        plain_text = cryptor.decrypt(base64.b64decode(text))
        return plain_text.rstrip('\0')


def mytarget(connect):

    # 身份验证：发出请求的用户是否存在
    user = connect.recv(1024)
    if user in dict:
        connect.send("yes")
        pw = dict[user]
        print "user is " + user
    else:
        connect.send("no")
        print "user error"
        connect.close()
        exit(-1)

    # 解密得到pkA
    ra = connect.recv(1024)
    pc = prpcrypt(pw)
    pkA = pc.decrypt(ra)
    print 'pkA: ' + pkA

    # 随机生成会话密钥Ks，双重加密发送给A
    a = [random.randint(0, 9) for _ in range(10)]
    Ks = ''.join(str(i) for i in a)
    print "Ks: " + Ks
    rsakey = RSA.importKey(pkA)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    cipher_text = base64.b64encode(cipher.encrypt(Ks))
    pc = prpcrypt(pw)
    e = pc.encrypt(cipher_text)
    connect.send(e)

    # 解密得NA，随机生成NB
    data = connect.recv(1024)
    pc = prpcrypt(Ks)
    NA = pc.decrypt(data)
    print 'NA: ' + NA
    a = [random.randint(0, 9) for _ in range(10)]
    NB = ''.join(str(i) for i in a)

    # 以Ks加密NA||NB并发送给A
    NA_B = NA + NB
    pc = prpcrypt(Ks)
    e = pc.encrypt(NA_B)
    connect.send(e)

    # 解密得N2，判断N2是否等于NB
    data = connect.recv(1024)
    pc = prpcrypt(Ks)
    N2 = pc.decrypt(data)
    if N2 == NB:
        print "Authentication success"
    else:
        print "Authentication faild"

    while True:
        data = connect.recv(1024)
        if data == "quit":
            print "User " + user + " quit!"
            break
        print "User " + user + " say: " + data
        connect.send("receive " + data)
    connect.close()
    # socket.close()


address = ('127.0.0.1', 31500)
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind(address)
socket.listen(5)

while True:
    connect, addr = socket.accept()
    print 'got connected from', addr
    chat = threading.Thread(target=mytarget, args=(connect,))
    chat.start()
socket.close()