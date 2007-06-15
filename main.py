from Crypto.Cipher import AES
import hashlib
import pickle

class CypherText:

	def __init__(self):
		self.__CypherText = ''
		self.__trailLen = 0
		
	def getCypherText(self):
		return self.__CypherText
		
	def setCypherText(self, CText):
		self.__CypherText = CText
		
	def setTrail(self, TLen):
		self.__trailLen = TLen
		
	def getTrail(self):
		return self.__trailLen
	
	
def hashPassword_MD5(Password):
	m = hashlib.md5()
	m.update(Password)
	return m.hexdigest()
	
def read_keys_from_file():
	f = open('./keys.txt','r')
	
	key = ''

	for line in f.readlines():
		if line.find('PUBLIC_KEY = ') != -1:
			key = line.strip('PUBLIC_KEY = ')
	
	if key == '' or len(key) != 32: 
		return -1
	else:
		return key
	
	
def encrypt(message, key):

	TrailLen = 0
	#AES requires blocks of 16
	while (len(message) % 16) != 0:
		message  = message + '_'
		TrailLen = TrailLen + 1
	
	CypherOut = CypherText()
	CypherOut.setTrail(TrailLen)
	
	cryptu = AES.new(key, AES.MODE_ECB)
	CypherOut.setCypherText( cryptu.encrypt(message) )
	return CypherOut
	
def decrypt(ciphertext, key):
	cryptu = AES.new(key, AES.MODE_ECB)
	message_n_trail = cryptu.decrypt(ciphertext.getCypherText())
	return message_n_trail[0:len(message_n_trail) - ciphertext.getTrail()]

def cryptFile(filename_in, filename_out, key):
	fr = open (filename_in, 'rb')
	fileContent = fr.read()
	
	cyphertext = encrypt(fileContent, PublicKey )
	
	fw = open (filename_out, 'wb')
	
	pickle.dump( cyphertext, fw, -1 )
	
def decryptFile(filename_in, filename_out, key):
	fr = open(filename_in, 'rb')
	
	cyphertext = pickle.load(fr)
	message = decrypt(cyphertext, key)
	
	fw = open(filename_out, 'wb')
	fw.write(message)
	

PublicKey = read_keys_from_file()
#cyphertext = encrypt( 'Boobies!', PublicKey )
#print decrypt( cyphertext, PublicKey )

#cryptFile('TestFile.jpg', 'CryptFile.jpg', PublicKey)
#decryptFile('CryptFile.jpg', 'decryptFile.jpg', PublicKey)

def getManual():
	man = 'Incorrect use, please observe the following protocol:\n'
	man += 'PyCrypt -encode Filename_in Filename_out Password\n'
	man += 'PyCrypt -decode Filename_in Filename_out Password\n'
	return man

if (__name__ == '__main__'):
	#Parse arguments
	print getManual()
