import os
import sys
import json
import base64
import hashlib
import getpass
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ret = base64.b64encode(iv + cipher.encrypt(raw.encode()))
        return ret.decode()

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

def init(fname, key):
    aes = AESCipher(key)
    keys = []
    keys_str = json.dumps(keys)
    keys_cipher = aes.encrypt(keys_str)
    with open(fname, 'w') as f:
        f.write(keys_cipher)

def store(fname, key, d):
    aes = AESCipher(key)
    d_cipher = aes.encrypt(json.dumps(d))
    with open(fname, 'w') as f:
        f.write(d_cipher)

def get_keys(fname, key):
    aes = AESCipher(key)
    with open(fname, 'r') as f:
        keys_cipher = f.read().strip()
    keys_str = aes.decrypt(keys_cipher)
    keys = json.loads(keys_str)
    return keys

def put(fname, key, label, secret):
    aes = AESCipher(key)
    keys = get_keys(fname, key)
    secret_cipher = aes.encrypt(secret)
    keys.append({ 'label': label, 'secret': secret_cipher })
    store(fname, key, keys) 

def get(fname, key, label):
    aes = AESCipher(key)
    keys = get_keys(fname, key)
    flag = False
    for key in keys:
        if key['label'] == label:
            print(label + ": " + aes.decrypt(key['secret']))
            flag = True
    if not flag:
        print('label not found')

def print_labels(fname, key, label=None):
    keys = get_keys(fname, key)
    labels = [key['label'] for key in keys]
    flag = False
    for l in labels:
        if label:
            if label in l:
                print(l)
                flag = True
        else:
            print(l)
            flag = True
    if label and not flag:
        print('label not found')
 
def print_all(fname, key, label=None):
    aes = AESCipher(key)
    keys = get_keys(fname, key)
    flag = False
    for key in keys:
        if label:
            if label in key['label']:
                print(key['label'] + ": " + aes.decrypt(key['secret']))
                flag = True
        else:
            print(key['label'] + ": " + aes.decrypt(key['secret']))
            flag = True
    if label and not flag:
        print('label not found')

if __name__ == "__main__":
    key = getpass.getpass()
    if len(sys.argv) < 3:
        print('usage: python3 main.py filepath store/get/getlabels/getall label')
        exit()
    fname = sys.argv[1]
    if not os.path.exists(fname):
        init(fname, key)
    if sys.argv[2] == 'put':
        label = sys.argv[3]
        secret = input('secret:')
        put(fname, key, label, secret)
    elif sys.argv[2] == 'get':
        label = sys.argv[3]
        get(fname, key, label)
    elif sys.argv[2] == 'getlabels':
        label = None
        if len(sys.argv) == 4:
            label = sys.argv[3]
        print_labels(fname, key, label)
    elif sys.argv[2] == 'getall':
        label = None
        if len(sys.argv) == 4:
            label = sys.argv[3]
        print_all(fname, key, label)
    else:
        print('command not found')
