#AES, from PyCrypto lib
from Crypto.Cipher import AES
#For MD5 hash
import hashlib
#Save/load in files
import pickle
#Argument parsing
import sys, getopt

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
	cyphertext = encrypt(fileContent, key )
	fw = open (filename_out, 'wb')
	pickle.dump( cyphertext, fw, -1 )
	
def decryptFile(filename_in, filename_out, key):
	fr = open(filename_in, 'rb')
	cyphertext = pickle.load(fr)
	message = decrypt(cyphertext, key)
	fw = open(filename_out, 'wb')
	fw.write(message)

def getManual():
	man = 'Usage:\n'
	man += 'PyCrypt -encode Filename_in Filename_out Password\n'
	man += 'PyCrypt -decode Filename_in Filename_out Password\n'
	man += "\nFor more info, please visit the project's homepage at:\n"
	man += "http://reachme.web.googlepages.com/pycrypt\n"
	return man

__doc__ = """
System exit code:
2 : Argument parsing error
-1: Error/Crash, please report
"""

#Returns the parameters of execution of the program
def parseCommandLine():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hed", ["help","encode","decode"])
	except getopt.error, msg:
		print 'Cannot parse arguments:'
		print msg
		print '\n' + getManual()
		sys.exit(2)
	
	method = ''
	
	#Process options
	for o, a in opts:

		if o in ("-h", "--help"):
			print getManual()
			sys.exit(0)
			
		elif o in ("-d", "--decode"):
			method = 'decode'
		elif o in ("-e", "--encode"):
			method = 'encode'
		else:
			print 'Invalid option.'
			print getManual()
			sys.exit(2)
	
	if len(args) != 3:
		print 'Incorrect number of arguments.'
		print getManual()
		sys.exit(2)
	
	filename_in = args[0]
	filename_out = args[1]
	password = args[2]
		
	return (method, filename_in, filename_out, password)

def checkProgArgs(method, filename_in, filename_out, password):
	if (method != 'encode') and (method != 'decode'):
		print 'ERROR: invalid method: ' + method
		sys.exit(-1)
		
	if filename_in == filename_out:
		print 'ERROR: filename_in == filename_out.'
		sys.exit(-1)
	
	#++check the existense of filename_in and inexistence of filename_out
	
	return 0

if (__name__ == '__main__'):
	#Parse command line options
	(method, filename_in, filename_out, password) = parseCommandLine()
	checkProgArgs(method, filename_in, filename_out, password)
	print (method, filename_in, filename_out, password)
	
	if method == 'encode':
		cryptFile(filename_in, filename_out, hashPassword_MD5(password))
	elif method == 'decode':
		decryptFile(filename_in, filename_out, hashPassword_MD5(password))

#PublicKey = read_keys_from_file()
#cyphertext = encrypt( 'Boobies!', PublicKey )
#print decrypt( cyphertext, PublicKey )
#cryptFile('TestFile.jpg', 'CryptFile.jpg', PublicKey)
#decryptFile('CryptFile.jpg', 'decryptFile.jpg', PublicKey)

