### Security module ### 
#
# Contains all the auxiliary functions to implement security measures on the application

import os
import base64
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, dh, ec
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import exceptions
import cryptography as c

# generate a new key pair value of assymetric keys (private,public)
# public key is serialized
def newRSAKeyPair():
	priv_key = rsa.generate_private_key(public_exponent=655537,key_size=2048,backend=default_backend())
	pub_key = priv_key.public_key()
	pub_key = pub_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
	return (priv_key,pub_key)

# serialize key as PEM format from object
def serializeKey(key):
	return key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

# load key object from given key in PEM format
def undoSerializeKey(key):
	return serialization.load_pem_public_key(key,backend=default_backend())

# generate a random key to be used in symmetric encryption (32 bytes <-> 256 bits)
def newSymmKey():
	return base64.b64encode(os.urandom(32))

# generate digest of data input using SHA256
def digestSHA256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    hash =  digest.finalize()
    return base64.b64encode(hash)

# AES encryption of data with key "key" and cipher mode CTR
def encryptAES(data, key):
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CTR(iv), default_backend())
	encryptor = cipher.encryptor()
	encData = encryptor.update(data) + encryptor.finalize()
	return base64.b64encode(encData), base64.b64encode(iv)

# AES decryption of ciphertext with key "key", initialization vector "iv" and cipher mode CTR
def decryptAES(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# encrypt message using RSA algorithm
def encryptRSA(pub_key, message):
	ciphertext = pub_key.encrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
	return base64.b64encode(ciphertext)

# decrypt ciphertext using RSA algorithm 
def decryptRSA(priv_key,ciphertext):
	message = priv_key.decrypt(base64.b64decode(ciphertext),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(),label=None))
	return message

# create signature from data using given private key 
def signRSA(priv_key, message):
	signature = priv_key.sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
	return signature

# validate a given signature of the message data
def validateRSA(pub_key, signature, message):
	try:
		pub_key.verify(signature,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
	except exceptions.InvalidSignature:
		print("Error: Signature is not valid")
		return -1
	print("Signature is valid")
	return 1

# generate a key from the given private and public values
def generateECDH_SharedKey(private_key,public_key):
	return private_key.exchange(ec.ECDH(),public_key)

# generate public and private diffie-hellman values using 
# elliptic curves algorithm
def generateECDHKeyPair():
    private_key = ec.generate_private_key(ec.SECP384R1(),default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# extend the given key to a 32 byte (256 bits) one
# to be used in AES criptographic operations
def hkdfeKeyDerivation(key):
	hkdf = HKDFExpand(algorithm=hashes.SHA256(),length=32,info=None,backend=default_backend())
	return hkdf.derive(key)

# calculate a HMAC value from the given data and simmetric key
def generateHMAC(key,data):
	h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
	h.update(data)
	return h.finalize()

# validates de received HMAC by generating a new one from 
# the given data and comparing them. If they're equal
# then the received HMAC was produced with the same simmetric key and thus valid
def validateHMAC(key,data,hmac):
	new_hmac = generateHMAC(key,data)
	return True if new_hmac==hmac else False

# store a key in PEM format on a file on disk
# if its a public key to be stored standard file write is used
# if its a private key then private_bytes method is used and a password is required	
def storeKeyPEM(uid,key,type,password=None,path=""):
	if(type=='public'):
		fname = 'public_'+str(uid)+'.pem'
		pem = key
	elif(type=='private'):
		if(not password):
			print("Error: Password is required to store private key")
			return -1
		fname = 'private_'+str(uid)+'.pem'
		pem = key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(password))
	else:
		print("Error: Invalid key type. Can only be \"public\" or \"private\" type")
		return -1

	try:
		with open(path+fname,"w") as file:
			file.write(pem)
	except Exception:
		print("Error occurred while writing key on file")
		return -1
	return 1

# load a key saved on file as PEM format 
# if a public key is to be read then the reading is standard file read
# if its a private key then the password used to save it on file is required
def loadKeyPEM(uid,type,password=None,path=""):
	if(type=='public'):
		fname = 'public_'+str(uid)+'.pem'
		try:
			with open(path+fname, "rb") as key_file:
				key = key_file.read()
			key_file.close()
		except Exception:
			print("Error occurred loading key from file")
			return -1

	elif(type=='private'):
		if(not password):
			print("Error: Password is required to store private key")
			return -1
		fname = 'private_'+str(uid)+'.pem'
		try:
			with open(path+fname, "rb") as key_file:
				key = serialization.load_pem_private_key(
					key_file.read(),
					password=password,
					backend=default_backend())
			key_file.close()	
		except Exception, exc:
			print(exc)
			return -1
	else:
		print("Error: Invalid key type. Can only be \"public\" or \"private\" type")
		return -1
	return key

# enter password without echo on terminal
def passwordInput(label="Password"):
	os.system("stty -echo")
	try:
		password = raw_input('> '+label+': ')
	except:
		pass
	os.system("stty echo")
	#print("\n")
	return password


# function used to generate server public and private DH values
# only used to create the .pem files which already exist on the project folder
def generateServerDHValues():
	# Diffie-Hellman private/public values
	private_key, public_key = generateECDHKeyPair()
	public_key_pem = serializeKey(public_key)
	# random password 
	server_password = digestSHA256('/zM3r%\Y?,,nT{cN')
	# cipher private value with password and encode as pem format
	priv_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(server_password))
	
	priv_name = "private_dh_server.pem"
	pub_name = "public_dh_server.pem"

	try:
		with open(priv_name,"w") as file:
			file.write(priv_key_pem)
		with open(pub_name,"w") as file:
			file.write(public_key_pem)
	except Exception:
		print("Error occurred while writing key on file")
		return 
	return 


# generate public and private keys of the server
# only used to create the .pem files which already exist on the project folder
def generateServerKeyPair():
	priv_key = rsa.generate_private_key(public_exponent=655537,key_size=4096,backend=default_backend())
	pub_key = priv_key.public_key()
	pub_key = pub_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

	server_password = digestSHA256('/zM3r%\Y?,,nT{cN')
	priv_pem = priv_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(server_password))
	try:
		with open("private_key_server.pem","w") as file:
			file.write(priv_pem)
		with open("public_key_server.pem","w") as file:
			file.write(pub_key)
	except Exception:
		print("Error occurred while writing key on file")
		return 
	return