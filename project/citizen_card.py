### Citizen card module ### 
#
# Contains the auxiliary functions for communication between the application and the smartcard PKI

import PyKCS11
from OpenSSL import crypto
import base64

# returns the Citizen Card session (Pykcs11 object) on successful login
def getSession(pin=None,slot=0,lib='libpteidpkcs11.so'):
	pkcs11 = PyKCS11.PyKCS11Lib()
	pkcs11.load(lib)
	slots = pkcs11.getSlotList()
	if(len(slots)==0):
		print("No smartcard detected!")
		return -1
	session = pkcs11.openSession(slots[slot])
	try:
		session.login(pin)
	except:
		print("Invalid PIN")
		return -1
	return session

# loads public key certificate from user Citizen Card as a OpenSSL.crypto.X509 object
def getCCPublicKeyCertificate(session):
	# find certificate with label equal to public authentication certificate label
	certificate_objects = session.findObjects(template=[(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE'), 
														(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
	# find index where certificate starts
	cert_idx = str(certificate_objects).find("CKA_VALUE")
	# remove leading and ending strings to get certificate content (string representation of bytes)
	cert = str(certificate_objects)[cert_idx:-2].replace("CKA_VALUE: (","").split(", ")
	# convert certificate to bytes
	cert_encoded = ''.join(chr(int(i)) for i in cert)
	# decode certificate and load it as a X509 object
	certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_encoded)
	return certificate

# extract the common name,organization, serial number and country
# of the user from his authentication certificate
def getCertInfo(certificate):
	c_name = certificate.get_subject().CN
	org = certificate.get_subject().O
	s_numb = certificate.get_subject().serialNumber
	country = certificate.get_subject().C
	return {"c_name":c_name,"org":org,"s_numb":s_numb,"country":country}

def signDataCC(session,data):
	# SHA256 signing mechanism 
	mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)
	# authentication private key objects
	priv_obj = session.findObjects(template=[(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY'),
											(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
	# generate signature using private key
	sign = session.sign(priv_obj[0],data,mechanism)
	# convert list of bytes to characters (binary string)
	signature = ''.join(chr(i) for i in sign)
	return signature

def verifySignCC(data,signature,certificate):
	# verify signature using certificate public key
	key = certificate.get_pubkey()
	try:
		valid = crypto.verify(certificate,signature,bytes(data), b"sha256WithRSAEncryption")
	except Exception:
		return False
	return True if valid is None else False

# digest public key certificate and result its value as an integer value
def digestCertificate(certificate):
	byte_digest = certificate.digest(b"sha256")
	return int('0x'+byte_digest.replace(":",""),16)

# serialize the given certificate as PEM format
def serializeCertificate(certificate):
	return crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)

# generate a X509 certificate object from the given certificate
def loadCertificate(certificate):
	return crypto.load_certificate(crypto.FILETYPE_PEM, certificate)

# for a given certificate validate its chain of trust
def validateCertificateChain(certificate):
	return