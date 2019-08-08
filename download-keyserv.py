import requests
from re import findall
import base64
import sys
from Crypto import Random
from Crypto.Cipher import AES
import argparse
import traceback

parser = argparse.ArgumentParser()

parser.add_argument("url", help="Url of file")
# parser.add_argument("-k", "--key-server", default="eu.pool.sks-keyservers.net", \
                    # help="Keyserver to use")

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
        # print(repr(decr))
        try:
            return self.unpad(decr).decode('utf-8')#).decode('utf-8')
        except:
            return self.unpad(decr) # file

try:
		url = args.url

		file_name = url[url.index("@")+1:url.index("&")] #.replace('@','')
		aes_key = url[url.index("#")+1:url.index("#")+1+32]
		aes = AESCipher(aes_key.decode('hex'))
		# print file_name#, url
		response = requests.get(url, stream=True)
		print "Loading keyserver page..."
		total_length = response.headers.get('content-length')
		data=""
		if total_length is None:
			data = response.content
		else:
			dl = 0
			total_length = int(total_length)
			for d in response.iter_content(chunk_size=4096):
				dl += len(d)
				data += d
				done = int(50 * dl / total_length)
				percent = float(dl)/float(total_length)*100.0
				sys.stdout.write("\rDownloading [%s%s] %.2f%%" % ('=' * done, ' ' * (50-done), percent))    
				sys.stdout.flush()
		print "...DONE!"
		data = data.replace("&#x2F;", "/")
		if 'not found' in data.lower() or 'no results' in data.lower():
			print "404!"
			print data
			exit(1)
		# print "data: ",data

		data_cleaned = {}
		for x in findall(r'[0-9]{1,}\@[a-zA-Z0-9\/\+\=]{1,}', data):
			# print "x",x
			data_cleaned[int(x.split('@')[0])] = x.split('@')[1]#x.replace('&#x2F;','/').replace('class="uid">','').replace('</span>','').split('@')[1]

		# print data_cleaned

		with open(file_name,"wb") as handle:
			for x in range(len(data_cleaned.keys())):
				# print data_cleaned[x]
				data_cleaned[x] = aes.decrypt(base64.b64decode(data_cleaned[x]))
				handle.write(data_cleaned[x])
		print file_name + " has been downloaded."
except Exception as e:
	traceback.print_exc()
	print "Something went wrong please try again, check your input or try switching your computer on and off"
