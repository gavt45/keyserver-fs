import subprocess
import random
import string
import base64
import sys
import os
from Crypto import Random
from Crypto.Cipher import AES
import argparse

parser = argparse.ArgumentParser()

parser.add_argument("file", help="File to be uploaded")
parser.add_argument("-k", "--key-server", default="eu.pool.sks-keyservers.net", \
                    help="Keyserver to use")

args = parser.parse_args()


class AESCipher(object):
    def __init__(self, key): 
        self.key = bytes(key) #hashlib.sha256(key).digest()
    
    def pad(self, s):
        v1=s
        v2=(AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
        if sys.version_info[0] == 3:
            return v1+bytes(v2, 'utf-8')
        else:
            return v1+bytes(v2)
    def unpad(self, s):
		return s[0:-bytearray(s)[-1]]
    
    def encrypt(self, raw, do_b64=False):
        raw = self.pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        if do_b64:
            return base64.b64encode(iv + cipher.encrypt(raw))
        else:
            return iv+cipher.encrypt(raw)
    def decrypt(self, enc, do_b64=False):
        if do_b64:
            enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decr = cipher.decrypt(enc[AES.block_size:])
        try:
            return self.unpad(decr).decode('utf-8')#).decode('utf-8')
        except:
            return self.unpad(decr) # file

#check if input is a file
file_to_upload = args.file

if "." in args.file:
    domain = args.file[args.file.index("."):]
else:
    domain = ".com"

aes_key = os.urandom(16)
aes = AESCipher(aes_key)

#generate random data for credentials
user_name = ''.join(random.choice(string.ascii_uppercase) for _ in range(10))
email = ''.join(random.choice(string.ascii_uppercase) for _ in range(10)) + "@"\
        + ''.join(random.choice(string.ascii_uppercase) for _ in range(5)) + domain
passphrase = ''.join(random.choice(string.ascii_uppercase) for _ in range(5))

#any key server is good as it will propogate world wide
key_server = args.key_server

#unattended key generation
p = subprocess.Popen('gpg2 --batch --pinentry-mode=loopback --passphrase ' + passphrase +\
                    ' --quick-gen-key "' + user_name + ' ' + email + '" rsa1024',\
                     shell=True, stdout=subprocess.PIPE)
out, err = p.communicate()

#get pub key
p = subprocess.Popen('gpg2 --list-key --with-colons ' + email, shell=True, stdout=subprocess.PIPE)
out, err = p.communicate()
# parse out the key id so we can use it to send keys to the key servers
key = key = [x.replace(':', '').replace('fpr', '') for x in out.split() if "fpr" in x][0] 

#open file in binary and break it up into 1305byte chunks
chunk_list = []
with open(file_to_upload, 'rb') as infile:
    while True:
        chunk_in = infile.read(1305-16) # 16 bytes of IV
        if not chunk_in:
            break
        chunk = aes.encrypt(chunk_in)
        chunk_list.append(chunk)



#encode binary chunks into base64 strings
for i,x in enumerate(chunk_list):
    sys.stdout.write('\r')
    # the exact output you're looking for:
    done = int(50*i/len(chunk_list))
    sys.stdout.write("Adding key uid's: [%s%s] %.2f%% done" % ('='*done,' '*(50-done),(float(i)/float(len(chunk_list))*100.0)))
    sys.stdout.flush()
    new_uid = str(i) + "@" + base64.b64encode(x)
    p = subprocess.Popen("gpg2 --batch --pinentry-mode=loopback --passphrase " + passphrase\
                + " --quick-add-uid "  + email + " " + new_uid, shell=True, stdout=subprocess.PIPE)
    out, err = p.communicate()

print "\rdone!                                                                              "

print "\nsend keys to a server..."
p = subprocess.Popen("gpg2 --keyserver " + key_server + " --send-keys "\
                    + key, shell=True, stdout=subprocess.PIPE)
out, err = p.communicate()

print "remove keys when done as they are not needed anymore..."
p = subprocess.Popen("gpg --batch --yes --delete-secret-keys " + key +\
                "&& gpg --batch --yes --delete-keys " + key, shell=True, stdout=subprocess.PIPE)
out, err = p.communicate()

if not err:
    print "removing temp keys\n"
    print "It can take 3-10mins before your key appears on your chosen server\n"
    print "http://{}/pks/lookup?search={}&op=index#{}".format(key_server, email, aes_key.encode('hex'))
else:
    print "something went wrong try again"
