
import sys
import socket
import json
import base64
import threading

from security import *
from citizen_card import *

ADDR = "0.0.0.0" # Server address (local)
PORT = 8080  # port
BUFSIZE = 8192
TERMINATOR = "\r\n"
MSG_TERMINATOR = "\n\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)

class Client:

	message_counter = 0
	server_public_key = None
	session_key = None
	client = None

	def __init__(self, internal_id=None,uuid=None, session_key=None, public_key=None, private_key=None,password=None,session=None):
		self.internal_id = internal_id
		self.uuid = uuid
		self.session_key = session_key
		self.public_key = public_key
		self.private_key = private_key
		self.password = password
		self.session = session

		self.peers = {}

	def __str__(self):
		print("Client: internal id: %s\tunique user id: %s\tsession key: %s" % (self.internal_id,self.uuid,self.session_key))

	def addPeer(self,uid,pub_key,certificate):
		self.peers[uid] = (pub_key,certificate)

	# Sent by a client for checking the reception status of a message (if is has or not a receipt
	# and if it is valid)
	def statusMsg(self):
		new_msg = dict()
		new_msg["type"] = "status"
		new_msg["id"] = input("ID of the receipt box: ")
		new_msg["msg"] = raw_input("Sent message ID: ")	
		new_msg["msg_id"] = self.message_counter

		hmac = generateHMAC(client.session_key,str(json.dumps(new_msg))) 

		try:
			s.send(json.dumps({"message":json.dumps(new_msg),"hmac":base64.b64encode(hmac)})+TERMINATOR)
			try:
				data = json.loads(s.recv(BUFSIZE))
				if('error' not in data):
					if("message" in data and "hmac" in data):
						message = json.loads(data['message'])
						hmac = base64.b64decode(data['hmac'])
						valid_hmac = validateHMAC(self.session_key,str(json.dumps(message)),hmac)
						if(valid_hmac):
							print("HMAC is valid!")
						else:
							print("HMAC invalid!")
							return -1
						if len(message['result']['receipts'])==0:
							print("No Receipts Available")
						else:
							print(message['result']['receipts'])

						if(int(message['msg_id'])==self.message_counter):
							self.message_counter+=1
						else:
							print("Error: Message identifier does not match its counterpart message.")
							return -1

					else:
						print("Error: Message fields incorrect. Message dropped")
						return -1   
				else:
					print data['error']
					return
			except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return	
		except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return
		return

	# Sent by a client after receiving and validating a message from a message box
	def receiptMsg(self, uid, msgid):
		new_msg = dict()
		new_msg["type"] = "receipt"
		new_msg["msg_id"] = self.message_counter
		new_msg["id"] = uid
		new_msg["msg"] = msgid
		# the receipt field contains a signature over the plaintext message received,
		# calculated with the same credentials that the user uses to autenticate messages
		# to other users. Its contents will be stored next to the copy of the messages 
		# sent by a user, with an extension indicating the receipt reception dates
		new_msg["receipt"] = base64.b64encode(signDataCC(self.session,msgid))


		hmac = generateHMAC(client.session_key,str(json.dumps(new_msg))) 

		try:

			s.send(json.dumps({"message":json.dumps(new_msg),"hmac":base64.b64encode(hmac)})+TERMINATOR)
			try:
				data = json.loads(s.recv(BUFSIZE))
				if('error' not in data):
					if("message" in data and "hmac" in data):
						message = json.loads(data['message'])
						hmac = base64.b64decode(data['hmac'])
						valid_hmac = validateHMAC(self.session_key,str(json.dumps(message)),hmac)
						if(valid_hmac):
							print("HMAC is valid!")
						else:
							print("HMAC invalid!")
							return -1							
	
						if(int(message['msg_id'])==self.message_counter):
							self.message_counter+=1
										
						else:
							print("Error: Message identifier does not match its counterpart message.")
							return -1

					else:
						print("Error: Message fields incorrect. Message dropped")
						return -1	
				else:
					print data['error']
					return
			except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return -1

		except socket.error, exc:
			print("Exception socket.error : %s" % exc)
			return -1

		return

	# Sent by a client in order to receive a message from a user's message box
	def recvMsg(self):

		new_msg = dict()
		new_msg["type"] = "recv"
		uid = int(input("User ID: "))
		new_msg["id"] = uid
		msgid = raw_input("Message ID: ")
		new_msg["msg"] = msgid
		new_msg["msg_id"] = self.message_counter

		hmac = generateHMAC(client.session_key,str(json.dumps(new_msg))) 

		try:
			s.send(json.dumps({"message":json.dumps(new_msg),"hmac":base64.b64encode(hmac)})+TERMINATOR)
			try:
				data = json.loads(s.recv(BUFSIZE))
				if('error' not in data):
					if("message" in data and "hmac" in data):
						message = json.loads(data['message'])
						hmac = base64.b64decode(data['hmac'])
						valid_hmac = validateHMAC(self.session_key,str(json.dumps(message)),hmac)
						if(valid_hmac):
							print("HMAC is valid!")
						else:
							print("HMAC invalid!")
							return -1      

						iv = message['result'][1].split(',')[2].split('"')[3]
						k = message['result'][1].split(',')[1].split('"')[3]
						emsg = message['result'][1].split(',')[0].split('"')[3]	
						print "Source ID:"+str(message['result'][0])+" Message:"+str(emsg)
						#deciphkey = decryptRSA(self.private_key, base64.b64decode(k))
						#deciphMSg = decryptAES(emsg, deciphkey, iv)
						if(int(message['msg_id'])==self.message_counter):
							self.message_counter+=1

						else:
							print("Error: Message identifier does not match its counterpart message.")
						self.receiptMsg(uid,msgid)
						return -1

					else:
						print("Error: Message fields incorrect. Message dropped")
						return -1   
				else:
					print data['error']
					return
			except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return
		except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return
		return

	# Sent by a client in order to list all new messages in a user message box
	def listAll(self):

		new_msg = dict()
		new_msg["type"] = "all"
		u_id = input("User ID: ")
		new_msg["id"] = u_id
		new_msg["msg_id"] = self.message_counter

		hmac = generateHMAC(client.session_key,str(json.dumps(new_msg))) 

		try:
			s.send(json.dumps({"message":json.dumps(new_msg),"hmac":base64.b64encode(hmac)})+TERMINATOR)
			try:	
				data = json.loads(s.recv(BUFSIZE))
				if('error' not in data):
					if("message" in data and "hmac" in data):
						message = json.loads(data['message'])
						hmac = base64.b64decode(data['hmac'])
						valid_hmac = validateHMAC(self.session_key,str(json.dumps(message)),hmac)
						if(valid_hmac):
							print("HMAC is valid!")
						else:
							print("HMAC invalid!")
							return -1                           
						print(message['result'])
					
						if(int(message['msg_id'])==self.message_counter):
							self.message_counter+=1

						else:
							print("Error: Message identifier does not match its counterpart message.")
							return -1

					else:
						print("Error: Message fields incorrect. Message dropped")
						return -1   
				else:
					print data['error']
					return
			except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return -1
		except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return
		return

	# list of messages not yet red by the user
	# Sent by a client in order to list all new messages in a user's message box
	def listNewRecvMsg(self):

		new_msg = dict()
		new_msg["type"] = "new"
		uid = input("User ID: ")
		new_msg["id"] = uid
		new_msg["msg_id"] = self.message_counter


		hmac = generateHMAC(client.session_key,str(json.dumps(new_msg))) 
		try:
			s.send(json.dumps({"message":json.dumps(new_msg),"hmac":base64.b64encode(hmac)})+TERMINATOR)
			try:	
				data = json.loads(s.recv(BUFSIZE))
				if('error' not in data):
					if("message" in data and "hmac" in data):
						message = json.loads(data['message'])
						hmac = base64.b64decode(data['hmac'])
						valid_hmac = validateHMAC(self.session_key,str(json.dumps(message)),hmac)
						if(valid_hmac):
							print("HMAC is valid!")
						else:
							print("HMAC invalid!")
							return -1
						if(uid == self.u_id):
							print(message['result'])
						else:
							print("Not allowed to see this message box!!")
						if(int(message['msg_id'])==self.message_counter):
							self.message_counter+=1

						else:
							print("Error: Message identifier does not match its counterpart message.")
							return -1

					else:
						print("Error: Message fields incorrect. Message dropped")
						return -1   
				else:
					print data['error']
					return
			except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return -1
		except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return
		return

	# Sent by a client in order to list users with a message box in the server
	def listMsg(self):

		print("1 - List all users message boxes")
		print("2 - List specific user message box")
		print("0 - Back")
		option = input("Option: ")

		new_msg = dict()
		new_msg["type"] = "list"
		new_msg["msg_id"] = self.message_counter

		if option == 1:
			try:
				hmac = generateHMAC(client.session_key,str(json.dumps(new_msg))) 
				s.send(json.dumps({"message":json.dumps(new_msg),"hmac":base64.b64encode(hmac)})+TERMINATOR)
				try:
					data = json.loads(s.recv(BUFSIZE))
					if('error' not in data):
						if("message" in data and "hmac" in data):
						    message = json.loads(data['message'])
						    hmac = base64.b64decode(data['hmac'])
						    valid_hmac = validateHMAC(self.session_key,str(json.dumps(message)),hmac)
						    if(valid_hmac):
						        print("HMAC is valid!")
						    else:
						        print("HMAC invalid!")
						        return -1                           
						    
						    print("List of users with message boxes on the server")
						    print((message.get("result")))

						    if(int(message['msg_id'])==self.message_counter):
						        self.message_counter+=1
						                    
						    else:
						        print("Error: Message identifier does not match its counterpart message.")
						        return -1

						else:
						    print("Error: Message fields incorrect. Message dropped")
						    return -1   
					else:
						print data['error']
						return
					
				except socket.error, exc:
					print("Exception socket.error : %s" % exc)
					return -1
			except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return

		if option == 2:
			try:
				u_id = input("User ID: ")
				new_msg["id"] = u_id # optional field
				hmac = generateHMAC(client.session_key,str(json.dumps(new_msg))) 
				s.send(json.dumps({"message":json.dumps(new_msg),"hmac":base64.b64encode(hmac)})+TERMINATOR)
				try:
					data = json.loads(s.recv(BUFSIZE))
					if('error' not in data):
						if("message" in data and "hmac" in data):
						    message = json.loads(data['message'])

						    print("List of users with message boxes on the server")
						    if(message.get("result")==None):
						    	print("User %d has no message box on the server" % u_id)
						    else:
						    	print("User %d has a message box on the server" % u_id)
						    	print(message.get("result"))

						    hmac = base64.b64decode(data['hmac'])
						    valid_hmac = validateHMAC(self.session_key,str(json.dumps(message)),hmac)
						    if(valid_hmac):
						        print("HMAC is valid!")
						    else:
						        print("HMAC invalid!")
						        return -1
						    if(int(message['msg_id'])==self.message_counter):
						        self.message_counter+=1
						    else:
						        print("Error: Message identifier does not match its counterpart message.")
						        return -1
						else:
						    print("Error: Message fields incorrect. Message dropped")
						    return -1   
					else:
						print data['error']
						return
					
				except socket.error, exc:
					print("Exception socket.error : %s" % exc)
					return -1
			except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return
		return

	def getRecipientPublicKey(self,dst_id):
		# retrieving recipient public key and authentication public key certificate
		msg = {}
		msg["type"] = "recipient_pk"
		msg['msg_id'] = self.message_counter
		msg["recipient"] = str(dst_id)

		hmac = generateHMAC(self.session_key,str(json.dumps(msg))) 

		print("CLIENT SESSION KEY %s " % self.session_key)

		try:
			s.send(json.dumps({"message":json.dumps(msg),"hmac":base64.b64encode(hmac)})+TERMINATOR)
			try:
				data = json.loads(s.recv(BUFSIZE))

				if('message' in data.keys() and 'hmac' in data.keys()):
					try:
						message = json.loads(data['message'])
					except:
						server_hmac = base64.b64decode(data['hmac'])
						valid_hmac = validateHMAC(self.session_key,str(json.dumps(data['message'])),server_hmac)
						if(valid_hmac):
							print("HMAC is valid!")
						else:
							print("HMAC invalid!")
							return -1
						print(data['message']['error'])
						return -1

					server_hmac = base64.b64decode(data['hmac'])

					valid_hmac = validateHMAC(self.session_key,str(json.dumps(message)),server_hmac)
					if(valid_hmac):
						print("HMAC is valid!")
					else:
						print("HMAC invalid!")
						return -1					

					if(message['msg_id']==self.message_counter):
						self.message_counter+=1

						certificate = base64.b64decode(message['public_key_certificate'])
						cert = loadCertificate(certificate)
						# validate recipient public key certificate 
						#
						#
						#
						#####

						# validate recipient public key 
						public_key = base64.b64decode(message['public_key'])

						public_key_sign = base64.b64decode(message['public_key_signature'])

						valid = verifySignCC(public_key,public_key_sign,cert)

						if(valid):
							print("Valid recipient public key signature")

							recipient_pk = public_key
							#print("\n\nRECIPIENT PUBLIC KEY %s\n\n" % recipient_pk)

							if(dst_id not in self.peers): # add new peer
								self.addPeer(dst_id,recipient_pk,certificate)
								print("Peer %s added to list of peers" % dst_id)
								print(self.peers)

						else:
							print("Invalid recipient public key signature")
							return -1

					else:
						print("Error: Message identifier does not match its counterpart message.")
						return -1

				else:
					print("Invalid message received from server while retrieving recipient public key")
					return -1

			except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return -1

		except socket.error, exc:
			print("Exception socket.error : %s" % exc)
			return -1

		return recipient_pk

	# message payload encrypted with destinatario public assymetric key. Whole msg encrypted with simmetric key
	# <msg> field contains the encrypted and signed message to be delivered to
	# the target message box; the server will not validate the message
	def sendMsg(self):

		dst = input("Destination ID: ")
		msg = raw_input("Message: ")

		if(dst in self.peers):
			print("User id %s is already known" % dst)
			pub_key = self.peers[int(dst)][0]
		else:
			pub_key = self.getRecipientPublicKey(dst)

		if(pub_key==-1):
			return -1

		# deserealize recipient public 
		r_pk = undoSerializeKey(pub_key)

		# generate new symmetric key to use to cipher the content of the message
		symmetric_key = newSymmKey()
		self.symmetric_key = symmetric_key

		new_msg = {}
		new_msg["type"] = "send"
		new_msg["msg_id"] = self.message_counter
		new_msg["src"] = self.client.internal_id
		new_msg["dst"] = int(dst)	# destination id
		new_msg["key"] = encryptRSA(r_pk,symmetric_key) # encrypt symmetric key with recipient public key
		ciphertext = encryptAES(msg,base64.b64decode(symmetric_key)) # # msg content, encrypted with generated symm key
		new_msg["msg"] = ciphertext[0] # ciphered message (b64 encoded)
		new_msg["iv"] = ciphertext[1] # initialization vector needed to decrypt (b64 encoded)

		print("\n\n\n\n %s \n\n\n" % self.client.public_key)

		# encrypted with sender public key so only him can access its content on the receipt box 
		new_msg["copy"] = encryptRSA(undoSerializeKey(self.client.public_key),msg) 

		hmac = generateHMAC(client.session_key,str(json.dumps(new_msg))) 

		try:

			s.send(json.dumps({"message":json.dumps(new_msg),"hmac":base64.b64encode(hmac)})+TERMINATOR)
			try:
				data = json.loads(s.recv(BUFSIZE))
				if("message" in data and "hmac" in data):
					message = json.loads(data['message'])
					hmac = base64.b64decode(data['hmac'])
					valid_hmac = validateHMAC(self.session_key,str(json.dumps(message)),hmac)
					if(valid_hmac):
						print("HMAC is valid!")
					else:
						print("HMAC invalid!")
						return -1

					if('error' not in message.keys()):
						print("Message sent successfully")
						if(int(message['msg_id'])==self.message_counter):
							self.message_counter+=1
							print(message['result'])
						else:
							print("Error: Message identifier does not match its counterpart message.")
							return -1
					else:
						print("Error: %s" % message)
				else:
					print("Error: Message fields incorrect. Message dropped")
					return -1				

			except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return -1

		except socket.error, exc:
			print("Exception socket.error : %s" % exc)
			return -1

		return

	# authenticates the user using the smartcard (Citizen Card)
	def smartcardAuthentication(self):
		auth_pin = str(passwordInput(label="Authentication PIN"))
		if((len(auth_pin)!=4) or (not auth_pin.isdigit())):
			print("Invalid PIN - PIN must be exactly 4 digits!")
			self.smartcardAuthentication()

		# we assume only one smartcard on each machine for now (slot=0)
		# authenticate using the user input PIN code
		session = getSession(auth_pin,0)
		if(session==-1):
			print("Smartcard authentication failed")
			sys.exit(0)
		else:
			print("Smartcard authentication successful")

		return session

	# generates a session key with the server using the diffie-hellman
	# key agreement method. Creates a private df value and a public one
	# which is sent to the server, properly signed using the clients CC
	def establishSessionKey(self,session):
		
		print("Generating Diffie-Hellman values...")
		# generate private/public client DH values
		client_private_dh,client_public_dh = generateECDHKeyPair()

		client_public_dh = serializeKey(client_public_dh)

		# server public diffie-hellman value is well-known to all clients so no need to make a request for it
		# load the public component of the server from file
		server_public_dh = loadKeyPEM('dh_server','public',path="KeysClientSide/")

		session_key = generateECDH_SharedKey(client_private_dh,undoSerializeKey(server_public_dh))

		print("\n\nSession KEY CLIENT %s" % session_key)

		# message to send client public dh component to server
		message = {}
		message['type'] = "dh"
		# message unique id (in order to guarantee that the server reply originated from processing this message)
		# since it is the first message we send to the server we start at 0 and increment after server reply
		message['msg_id'] = self.message_counter
		# public value base 64 encoded
		message['value'] = base64.b64encode(client_public_dh)
		# digital signature of public dh component with citizen card private authentication key
		print("Signing public diffie-hellman value...")
		message['value_signed'] = base64.b64encode(signDataCC(session,client_public_dh))
		# the authentication public key certificate extracted from the user citizen card serialized as PEM and encoded w/ b64
		certificate = getCCPublicKeyCertificate(session)
		message['pub_key_certificate'] = base64.b64encode(serializeCertificate(certificate))
		
		try:
			s.connect((ADDR, PORT))
			s.send(json.dumps(message)+TERMINATOR)
			
			try:
				data = json.loads(s.recv(BUFSIZE))
				
				if("message" in data and "signature" in data):
					message = data['message']
					signature = data['signature']
					# load server public key from file
					self.server_public_key = undoSerializeKey(loadKeyPEM("key_server",'public',path="KeysServerSide/"))
					# always validate the message first to make sure we can trust its content
					valid = validateRSA(self.server_public_key,base64.b64decode(signature),str(message))
					message = json.loads(message)
					if(valid):
						# verify is the server response has the same message identifier of its counterpart
						if(int(message['msg_id'])==self.message_counter):
							self.message_counter+=1
							if("error" in message.keys()):
								print("Error: %s" % message['error'])
								return -1
							print("Session key established successfully")
						else:
							print("Error: Message identifier does not match its counterpart message.")
							return -1
					else:
						print("Error: Invalid message signature. Message dropped")
						return -1
				else:
					print("Error: Message fieds incorrect. Message dropped")
					return -1
			except socket.error, exc:
				print("Exception socket.error : %s" % exc) 
		except socket.error, exc:
			print("Exception socket.error : %s" % exc)
			return -1

		return session_key,client_public_dh,certificate

	## autentication method - autenticates user on the server
	## before any communication with the server generate the symmetric 
	## session key using diffie-hellman 
	## Create a user message box for the user 
	## <uuid> is the digest of the public key of the client (extracted from his public key certificate)
	## <other atributes> contains the public key certificate (authentication key and signature key)
	## whole message is encrypted with the temporary session symmetric key 
	def authentication(self):

		# smartcard autentication
		session = self.smartcardAuthentication()
		self.session = session

		# first step is to establish a shared session key with the server
		print("\nInitiating session with server...")
		session_init = self.establishSessionKey(session)
		if(session_init==-1):
			print("Error occurred while generating session key.\nNow exiting...")
			return -1

		session_key = session_init[0]
		client_public_dh = session_init[1]
		certificate = session_init[2]

		create_msg = {}
		create_msg["type"] = "create"
		create_msg["msg_id"] = self.message_counter
		create_msg["uuid"] = digestCertificate(certificate) # digest of user public key certificate

		create_msg["public_key_certificate"] = base64.b64encode(serializeCertificate(certificate))

		# new assymetric key pair generation
		# may be discarded if the client already has a message box on the server
		# not the optimal way...

		(private_key,public_key) = newRSAKeyPair()

		create_msg["public_key"] = base64.b64encode(public_key)

		create_msg["client_public_dh"] = base64.b64encode(client_public_dh)

		print("Signing public key...")
		pub_key_sign = base64.b64encode(signDataCC(session,public_key))
		print("Signing public key certificate...")
		cert_sign = base64.b64encode(signDataCC(session,serializeCertificate(certificate)))
		create_msg["public_key_signature"] = pub_key_sign

		create_msg["certificate_signature"] = cert_sign

		# generate HMAC of CREATE message 
		hmac = generateHMAC(session_key,str(json.dumps(create_msg)))

		msg = {"message":json.dumps(create_msg), "hmac":base64.b64encode(hmac)}

		user_id = create_msg["uuid"]

		try:
			s.connect((ADDR, PORT))
			s.send(json.dumps(msg)+TERMINATOR)
			print("\nChecking if existing message box...")
			try:
				# server replies with the internal identifier given to the user
				data = json.loads(s.recv(BUFSIZE))
				message = json.loads(data['message'])
				hmac = base64.b64decode(data['hmac'])
				# validate received message HMAC
				valid_hmac = validateHMAC(session_key,str(json.dumps(message)),hmac)
				if(valid_hmac):
					print("HMAC is valid!")
				else:
					print("HMAC invalid!")
					return -1

				if(int(message['msg_id'])==self.message_counter):
					self.message_counter+=1
					if("error" in message.keys()):
						print("Error: %s" % message['error'])
						return -1

					if(message['new_account']==1):
						if('result' in message):
							print("New message box created")
							# password to safely store/load user private key on disk
							while True:
								print("Enter private key password")
								password = passwordInput()
								print("\nRe-enter private key password")
								password1 = passwordInput()

								if(password!=password1):
									print("Passwords do no match!")
								else:
									break

							pwd = digestSHA256(password)
							del password
							del password1
							u_id = int(message["result"])
							storeKeyPEM(u_id,public_key,'public')
							storeKeyPEM(u_id,private_key,'private',pwd)
						else:
							print("Error retrieving user ID")
							return -1

					elif(message['new_account']==0):
						print("User already has message box on the server.")
						if('result' in message):
							u_id = int(message["result"])
							self.u_id = u_id
							print("Internal user ID %s" % u_id)
							print("Enter private key password")
							password = passwordInput()
							print("\n")
							pwd = digestSHA256(password)
							public_key = loadKeyPEM(u_id,"public")
							private_key = loadKeyPEM(u_id,"private",pwd)
							self.private_key = private_key

							if(public_key==-1 or private_key==-1):
								return -1

						else:
							print("Error retrieving user ID")
							return -1
					else:
						print("Error ocurred while creating message box")
						return -1

			except socket.error, exc:
				print("Exception socket.error : %s" % exc)
				return -1

		except socket.error, exc:
			print("Exception socket.error : %s" % exc)
			return -1

		# init the client
		self.client = Client(u_id, user_id, session_key,public_key,private_key,pwd,session)
		client = Client(u_id, user_id, session_key,public_key,private_key,pwd,session)

		self.session_key = session_key

		return client

	## Client initiates session with the server
	def initSession(self):
		return self.authentication()

	## Close session with the server
	## Erase the temporary symmetric key to communicate with the server
	def logOut(self):
		print("\nClosing session with the server...")
		try:
			s.close()
		except socket.error, exc:
			print("Exception socket.error : %s" % exc)
		print("Bye!")
		sys.exit(0)

	## Client processes
	def clientManager(self):
		print("\n>>>> Available operations")
		print("1 - Send new message")
		print("2 - List users' message boxes")
		print("3 - List new received messages by users")
		print("4 - List all messages received by a user")
		print("5 - Receive message from a user message box")
		print("6-  List messages sent and their receipts")
		print("0 - Log out")
		return input("Option > ")

	def optionManager(self,flag):

		# initSession on first call of optionManager()
		if(flag==0):
			client = self.initSession()
			if(client == -1 ):
				return

		c_option = self.clientManager()

		while(c_option!=0):

			if c_option == 1:
				print("\n>>>> Send new message")
				self.sendMsg()
				self.optionManager(1)
				return

			if c_option == 2:
				print("\n>>>> List users messages boxes")
				self.listMsg()
				self.optionManager(1)
				return

			if c_option == 3:
				print("\n>>>> List new received messages by users")
				self.listNewRecvMsg()
				self.optionManager(1)
				return

			if c_option == 4:
				print("\n>>>> List all messages received by a user")
				self.listAll()
				self.optionManager(1)
				return

			if c_option == 5:
				print("\n>>>> Receive message from a user message box")
				self.recvMsg()
				self.optionManager(1)
				return

			if c_option == 6:
				print("\n>>>> List messages sent and their receipts")
				self.statusMsg()
				self.optionManager(1)
				return

		self.logOut()
		return

if __name__ == '__main__':

	print("\n>>>> Secure Client Message Interface")
	client = Client()
	client.optionManager(0)
	try:
		client.session.logout()
		client.session.closeSession()
	except Exception:
		pass
	os.system("stty echo")
	print("\n")
	print("Bye!")