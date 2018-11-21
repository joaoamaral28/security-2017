import logging
from log import *
from server_registry import *
from server_client import *
import json
import base64

from security import *


class ServerActions:
    def __init__(self):

        self.messageTypes = {
            'all': self.processAll,
            'list': self.processList,
            'new': self.processNew,
            'send': self.processSend,
            'recv': self.processRecv,
            'create': self.processCreate,
            'receipt': self.processReceipt,
            'status': self.processStatus,
            'dh' : self.processDiffieHellman, 
            'recipient_pk':self.processRecipientPublicKey, 
        }

        self.registry = ServerRegistry()

    def handleRequest(self, s, request, client):
        """Handle a request from a client socket.
        """
        print("server_actions handleRequest()")
        try:
            logging.info("HANDLING message from %s: %r" %
                         (client, repr(request)))

            try:
                req = json.loads(request)
            except:
                logging.exception("Invalid message from client")
                return

            if not isinstance(req, dict):
                log(logging.ERROR, "Invalid message format from client")
                return

            if 'message' not in req:
                if 'type' not in req:
                    log(logging.ERROR, "Message has no TYPE field")
                    return
    
            if('type' in req):
                if req['type'] in self.messageTypes:
                    self.messageTypes[req['type']](req, client)
            elif('type' in json.loads(req['message'])): 
                message = json.loads(req['message'])
                if(message['type'] in self.messageTypes):
                    self.messageTypes[message['type']](req, client)   
            else:
                log(logging.ERROR, "Invalid message type: " +
                    str(req['type']) + " Should be one of: " + str(self.messageTypes.keys()))
                client.sendResult({"error": "unknown request"})

        except Exception, e:
            logging.exception("Could not handle request")

    def sendErrorMessage(self,client,label,msg_id,type=None):
        error_msg = {}
        error_msg["error"] = label
        error_msg["msg_id"] = msg_id

        if(type=='hmac'):
            hmac = generateHMAC(client.session_key,str(json.dumps(error_msg))) 
            client.sendResult({"message":error_msg, "hmac":base64.b64encode(hmac)})
        else:
            sign = signRSA(self.registry.server_private_key,str(error_msg))
            client.sendResult({"message":error_msg, "signature":base64.b64encode(sign)})
        return

    def processCreate(self, data, client):
        print("server_actions processCreate()")

        log(logging.DEBUG, "%s" % json.dumps(data))

        if 'message' not in data.keys():
            log(logging.ERROR, "No \"message\" field in \"create\" message: " +
                json.dumps(data))
            self.sendErrorMessage(client,"wrong message format", data["message"]['msg_id'])
            return

        if 'hmac' not in data.keys():
            log(logging.ERROR, "No \"hmac\" field in \"create\" message: " +
                json.dumps(data))
            self.sendErrorMessage(client,"wrong message format", data["message"]['msg_id'])
            return

        message = json.loads(data["message"])

        if 'msg_id' not in message.keys():
            log(logging.ERROR, "No \"msg_id\" field in \"create\" message: " +
                json.dumps(data))
            self.sendErrorMessage(client,"wrong message format", message['msg_id'])
            return

        if 'uuid' not in message.keys():
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            self.sendErrorMessage(client,"wrong message format", message['msg_id'])
            return

        if 'public_key_certificate' not in message.keys():
            log(logging.ERROR, "No \"public_key_certificate\" field in \"create\" message: " +
                json.dumps(data))
            self.sendErrorMessage(client,"wrong message format", message['msg_id'])
            return

        if 'public_key' not in message.keys():
            log(logging.ERROR, "No \"public_key\" field in \"create\" message: " +
                json.dumps(data))
            self.sendErrorMessage(client,"wrong message format", message['msg_id'])
            return

        if 'client_public_dh' not in message.keys():
            log(logging.ERROR, "No \"client_public_dh\" field in \"create\" message: " +
                json.dumps(data))
            self.sendErrorMessage(client,"wrong message format", message['msg_id'])
            return

        if 'public_key_signature' not in message.keys():
            log(logging.ERROR, "No \"public_key_signature\" field in \"create\" message: " +
                json.dumps(data))
            self.sendErrorMessage(client,"wrong message format", message['msg_id'])
            return

        if 'certificate_signature' not in message.keys():
            log(logging.ERROR, "No \"certificate_signature\" field in \"create\" message: " +
                json.dumps(data))
            self.sendErrorMessage(client,"wrong message format", message['msg_id'])
            return

        # first step is to validate the hmac of the received message
        client_hmac = base64.b64decode(data["hmac"])
        new_hmac = generateHMAC(client.session_key,str(json.dumps(message)))        
        valid_hmac = validateHMAC(client.session_key,str(json.dumps(message)),client_hmac)

        if(valid_hmac):
            print("HMAC is valid!")
        else:
            print("HMAC invalid!")
            self.sendErrorMessage(client,"Invalid HMAC", message['msg_id'])
            return

        # validate user public key certificate chain of trust
        #valid_cert = validateCertificateChain(certificate)
        #if(valid):
        #    print("Public key certificate is valid")
        #else:
        #    print("Public key certificate not valid!")
        #    self.sendErrorMessage(client,"Invadlid certificate",message['msg_id'])
        #    return

        cert = base64.b64decode(message["public_key_certificate"])

        # validate the public key authentication certificate signature
        valid_cert_sign = verifySignCC( cert,base64.b64decode(message["certificate_signature"]),loadCertificate(cert))
        if(valid_cert_sign):
            print("Public key certificate signature is valid")
        else:
            print("Public key certificate signature not valid!")
            self.sendErrorMessage(client,"Invalid certificate signature",message['msg_id'])
            return

        # validate the public key signature
        valid_key_sign = verifySignCC(base64.b64decode(message["public_key"]),base64.b64decode(message['public_key_signature']),loadCertificate(cert))
        if(valid_key_sign):
            print("Public key signature is valid")
        else:
            print("Public key certificate signature not valid!")
            self.sendErrorMessage(client,"Invalid certificate signature",message['msg_id'])
            return

        if 'uuid' not in message.keys():
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        if 'client_public_dh' not in message.keys():
            log(logging.ERROR, "No \"public dh value\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return


        try:
            uuid = int(message['uuid'])
        except Exception:
            if not isinstance(uuid, int):
                log(logging.ERROR, "No valid \"uuid\" field in \"create\" message: " +
                    json.dumps(data))
                client.sendResult({"error": "wrong message format"})
                return

        #if not isinstance(uuid, int):
        #    log(logging.ERROR, "No valid \"uuid\" field in \"create\" message: " +
        #        json.dumps(data))
        #    client.sendResult({"error": "wrong message format"})
        #    return

        msg_id = message['msg_id']
        del message['msg_id']
        
        me = self.registry.addUser(message)

        msg = {}

        if(isinstance(me[0], int)):
            msg["result"] = me[0]
        else:
            msg["result"] = me[0].id

        msg["new_account"] = me[1]
        msg["msg_id"] = msg_id

        hmac = generateHMAC(client.session_key,str(json.dumps(msg))) 

        client.sendResult({"message":json.dumps(msg), "hmac":base64.b64encode(hmac)})

    def processList(self, data, client):
        print("server_actions processList()")
        log(logging.DEBUG, "%s" % json.dumps(data))

        message = json.loads(data['message'])

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in message.keys():
            user = int(message['id'])
            userStr = "user%d" % user
            if not set(message.keys()).issuperset(set({'id', 'msg_id'})):
                log(logging.ERROR, "Badly formated \"list\" message: " +
                    json.dumps(data))
                client.sendResult({"error": "wrong message format"})
                self.sendErrorMessage(client,"wrong message format", message['msg_id'], type="hmac") 

        client_hmac = base64.b64decode(data['hmac'])

        # validate HMAC received from server
        valid_hmac = validateHMAC(client.session_key,str(json.dumps(message)),client_hmac)
        if(valid_hmac):
            print("HMAC is valid!")
        else:
            print("HMAC invalid!")
            self.sendErrorMessage(client,"HMAC invalid", message['msg_id'], type="hmac") 

        msg_id = str(message['msg_id'])

        log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)

        msg = {}

        msg["result"] = userList
        msg['msg_id'] = msg_id

        hmac = generateHMAC(client.session_key,str(json.dumps(msg))) 

        client.sendResult({"message":json.dumps(msg), "hmac":base64.b64encode(hmac)})


    def processNew(self, data, client):
        print("server_actions processNew()")
        log(logging.DEBUG, "%s" % json.dumps(data))

        message = json.loads(data['message'])

        if not set(message.keys()).issuperset(set({'id', 'msg_id'})):
            log(logging.ERROR, "Badly formated \"new\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            sendErrorMessage()
            self.sendErrorMessage(client,"wrong message format", message['msg_id'], type="hmac") 


        client_hmac = base64.b64decode(data['hmac'])

        # validate HMAC received from server
        valid_hmac = validateHMAC(client.session_key,str(json.dumps(message)),client_hmac)
        if(valid_hmac):
            print("HMAC is valid!")
        else:
            print("HMAC invalid!")
            self.sendErrorMessage(client,"HMAC invalid", message['msg_id'], type="hmac") 


        user = -1
        if 'id' in message.keys():
            user = int(message['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        msg_id = str(message['msg_id'])

        newmsg = self.registry.userNewMessages(user)

        msg = {}

        msg["result"] = newmsg
        msg['msg_id'] = msg_id

        hmac = generateHMAC(client.session_key,str(json.dumps(msg))) 

        client.sendResult({"message":json.dumps(msg), "hmac":base64.b64encode(hmac)})

    def processAll(self, data, client):
        print("server_actions processAll()")
        log(logging.DEBUG, "%s" % json.dumps(data))

        message = json.loads(data['message'])

        if not set(message.keys()).issuperset(set({'id', 'msg_id'})):
            log(logging.ERROR, "Badly formated \"all\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            sendErrorMessage()
            self.sendErrorMessage(client,"wrong message format", message['msg_id'], type="hmac") 


        client_hmac = base64.b64decode(data['hmac'])

        # validate HMAC received from server
        valid_hmac = validateHMAC(client.session_key,str(json.dumps(message)),client_hmac)
        if(valid_hmac):
            print("HMAC is valid!")
        else:
            print("HMAC invalid!")
            self.sendErrorMessage(client,"HMAC invalid", message['msg_id'], type="hmac") 

        user = -1
        if 'id' in message.keys():
            user = int(message['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"all\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        msg_id = str(message['msg_id'])

        allmsg = self.registry.userAllMessages(user)
        allsent = self.registry.userSentMessages(user)
        msg = {}

        msg["result"] = [allmsg]+[allsent]
        msg['msg_id'] = msg_id

        hmac = generateHMAC(client.session_key,str(json.dumps(msg))) 

        client.sendResult({"message":json.dumps(msg), "hmac":base64.b64encode(hmac)})

    def processSend(self, data, client):
        print("server_actions processSend()")
        
        log(logging.DEBUG, "%s" % json.dumps(data))

        message = json.loads(data['message'])

        if not set(message.keys()).issuperset(set({'src','msg_id', 'dst', 'msg', 'copy', 'key', 'iv'})):
            log(logging.ERROR,
                "Badly formated \"send\" message: " + json.dumps(data))
            sendErrorMessage()
            self.sendErrorMessage(client,"wrong message format", message['msg_id'], type="hmac") 

        client_hmac = base64.b64decode(data['hmac'])

        # validate HMAC received from server
        valid_hmac = validateHMAC(client.session_key,str(json.dumps(message)),client_hmac)
        if(valid_hmac):
            print("HMAC is valid!")
        else:
            print("HMAC invalid!")
            self.sendErrorMessage(client,"HMAC invalid", message['msg_id'], type="hmac") 

        srcId = int(message['src'])
        dstId = int(message['dst'])
        msg = str(message['msg'])
        msg_id = str(message['msg_id'])
        copy = str(message['copy'])
        key = str(message['key'])
        iv = str(message['iv'])

        if not self.registry.userExists(srcId):
            log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        if not self.registry.userExists(dstId):
            log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        # Save message and copy
        response = self.registry.sendMessage(srcId, dstId, msg, copy, key, iv)
        ######################################################################
        msg={}
        msg['result'] = response
        msg['msg_id'] = msg_id

        hmac = generateHMAC(client.session_key,str(json.dumps(msg))) 

        client.sendResult({"message": json.dumps(msg), "hmac":base64.b64encode(hmac)})

    def processRecv(self, data, client):
        print("server_actions processRecv()")
        log(logging.DEBUG, "%s" % json.dumps(data))

        message = json.loads(data['message'])

        if not set(message.keys()).issuperset(set({'id', 'msg', 'msg_id'})):
            log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            sendErrorMessage()
            self.sendErrorMessage(client,"wrong message format", message['msg_id'], type="hmac") 

        client_hmac = base64.b64decode(data['hmac'])

        # validate HMAC received from server
        valid_hmac = validateHMAC(client.session_key,str(json.dumps(message)),client_hmac)
        if(valid_hmac):
            print("HMAC is valid!")
        else:
            print("HMAC invalid!")
            self.sendErrorMessage(client,"HMAC invalid", message['msg_id'], type="hmac") 


        fromId = int(message['id'])
        msg = str(message['msg'])
        msg_id = str(message['msg_id'])

        if not self.registry.userExists(fromId):
            log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "Unknown source id for \"recv\" message"})
            return

        if not self.registry.messageExists(fromId, msg):
            log(logging.ERROR,
                "Unknown source msg for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "Unknown source msg for \"recv\" message"})
            return

        # Read message

        response = self.registry.recvMessage(fromId, msg)
        print response
        msg = {}

        msg["result"] = response
        msg['msg_id'] = msg_id

        hmac = generateHMAC(client.session_key,str(json.dumps(msg))) 

        client.sendResult({"message":json.dumps(msg), "hmac":base64.b64encode(hmac)})

    def processReceipt(self, data, client):
        print("server_actions processReceipt()")
        log(logging.DEBUG, "%s" % json.dumps(data))

        message = json.loads(data['message'])

        if not set(message.keys()).issuperset(set({'id', 'msg', 'receipt','msg_id'})):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            sendErrorMessage()
            self.sendErrorMessage(client,"wrong message format", message['msg_id'], type="hmac") 

        client_hmac = base64.b64decode(data['hmac'])

        # validate HMAC received from server
        valid_hmac = validateHMAC(client.session_key,str(json.dumps(message)),client_hmac)
        if(valid_hmac):
            print("HMAC is valid!")
        else:
            print("HMAC invalid!")
            self.sendErrorMessage(client,"HMAC invalid", message['msg_id'], type="hmac") 

        fromId = int(message["id"])
        msg = str(message['msg'])
        receipt = str(message['receipt'])
        msg_id = str(message['msg_id'])

        if not self.registry.messageWasRed(str(fromId), msg):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            client.sendResult({"error": "Unknown, or not yet red, message for \"receipt\" request"})
            return

        my_receipt = self.registry.getReceipts(fromId, msg)
        for a in range(len(my_receipt["receipts"])):
            print my_receipt["receipts"][a]['receipt']
            if receipt in my_receipt["receipts"][a]['receipt']:
                log(logging.ERROR, "Receipt already in \"receipt\" box: " +
                json.dumps(data))
                client.sendResult({"error": "Receipt already exists"})
                return
        
        self.registry.storeReceipt(fromId, msg, receipt)
        my_receipt = self.registry.getReceipts(fromId, msg)

        msg = {}

        msg["result"] = my_receipt
        msg['msg_id'] = msg_id

        hmac = generateHMAC(client.session_key,str(json.dumps(msg))) 

        client.sendResult({"message":json.dumps(msg), "hmac":base64.b64encode(hmac)})

    def processStatus(self, data, client):
        print("server_actions processStatus()")
        log(logging.DEBUG, "%s" % json.dumps(data))

        message = json.loads(data['message'])
        if not set(message.keys()).issuperset(set({'id', 'msg', 'msg_id'})):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            self.sendErrorMessage(client,"wrong message format", message['msg_id'], type="hmac") 

        client_hmac = base64.b64decode(data['hmac'])

        # validate HMAC received from server
        valid_hmac = validateHMAC(client.session_key,str(json.dumps(message)),client_hmac)
        if(valid_hmac):
            print("HMAC is valid!")
        else:
            print("HMAC invalid!")
            self.sendErrorMessage(client,"HMAC invalid", message['msg_id'], type="hmac") 
        
        fromId = int(message['id'])
        msg = str(message["msg"])
        msg_id = str(message['msg_id'])

        if(not self.registry.copyExists(fromId, msg)):
            log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
            client.sendResult({"error", "Unknown message for \"status\" request"})
            return

        response = self.registry.getReceipts(fromId, msg)

        msg = {}

        msg["result"] = response
        msg['msg_id'] = msg_id

        hmac = generateHMAC(client.session_key,str(json.dumps(msg))) 

        client.sendResult({"message":json.dumps(msg), "hmac":base64.b64encode(hmac)})


    def processDiffieHellman(self,data,client):

        log(logging.DEBUG, "%s" % data)

        # message structure validation
        if 'value' not in data.keys():
            log(logging.ERROR, "No \"value\" field in \"Diffie-Hellman\" message: " + json.dumps(data))
            error_msg = {}
            error_msg["error"] = "wrong message format"
            error_msg["msg_id"] = data['msg_id']
            sign = signRSA(self.registry.server_private_key,str(error_msg))
            client.sendResult({"message":error_msg, "signature":base64.b64encode(sign)})
            return

        if 'msg_id' not in data.keys():
            log(logging.ERROR, "No \"msg_id\" field in \"Diffie-Hellman\" message: " + json.dumps(data))
            error_msg = {}
            error_msg["error"] = "wrong message format"
            error_msg["msg_id"] = data['msg_id']
            sign = signRSA(self.registry.server_private_key,str(error_msg))
            client.sendResult({"message":error_msg, "signature":base64.b64encode(sign)})
            return

        if 'value_signed' not in data.keys():
            log(logging.ERROR, "No \"value_signed\" field in \"Diffie-Hellman\" message: " + json.dumps(data))
            error_msg = {}
            error_msg["error"] = "wrong message format"
            error_msg["msg_id"] = data['msg_id']
            sign = signRSA(self.registry.server_private_key,str(error_msg))
            client.sendResult({"message":error_msg, "signature":base64.b64encode(sign)})
            return

        if 'pub_key_certificate' not in data.keys():
            log(logging.ERROR, "No \"pub_key_certificate\" field in \"Diffie-Hellman\" message: " + json.dumps(data))
            error_msg = {}
            error_msg["error"] = "wrong message format"
            error_msg["msg_id"] = data['msg_id']
            sign = signRSA(self.registry.server_private_key,str(error_msg))
            client.sendResult({"message":error_msg, "signature":base64.b64encode(sign)})
            return

        certificate = loadCertificate(base64.b64decode(data['pub_key_certificate']))

        # validate user public key certificate chain of trust
        #valid_cert = validateCertificateChain(certificate)
        #if(valid):
        #    print("Public key certificate is valid")
        #else:
        #    print("Public key certificate not valid!")
        #    client.sendResult({"error": "Invalid certificate"})
        #    return

        client_public_dh = base64.b64decode(data['value'])

        # validate public dh component received from the client
        valid_sign = verifySignCC(client_public_dh,base64.b64decode(data['value_signed']),certificate)

        if(valid_sign):
            print("Public Diffie-Hellman value is valid")
        else:
            print("Public Diffie-Hellman value is not valid!")
            error_msg = {}
            error_msg["error"] = "Invalid signature"
            error_msg["msg_id"] = data['msg_id']
            sign = signRSA(self.registry.server_private_key,str(error_msg))
            client.sendResult({"message":error_msg, "signature":base64.b64encode(sign)})
            return

        ### validation step concluded ###

        # server private dh value 
        server_private_dh = self.registry.server_private_dh

        # session key generated from client public dh value and server private dh value
        session_key = generateECDH_SharedKey(server_private_dh,undoSerializeKey(client_public_dh))

        print("\n\nSession KEY SERVER %s \n\n\n\n\n" % session_key)
        
        # store this session key temporarily
        # this is done because session key is generated before there is an internal id 
        # given to the client trying to autenticate. Pending session keys are stored in 
        # a dict until server receives confirmation the client has a user ID. After that 
        #server can now associate the user internal id with the session key 
        # self.registry.addPendingSessionKey(client_public_dh,session_key)

        msg={}
        msg["type"] = "ack"
        msg["value"] = "OK"
        msg["msg_id"] = data['msg_id']

        # signing server response 
        json_msg = json.dumps(msg)

        sign = signRSA(self.registry.server_private_key,json_msg)  

        client.addSessionKey(session_key) 
     
        client.sendResult({"message":json_msg, "signature":base64.b64encode(sign)})
        
    def processRecipientPublicKey(self,data,client):

        log(logging.DEBUG, "%s" % data)

        print("\n\n\n\n %s \n\n\n" % self.registry.users)

        message = json.loads(data['message'])

        if 'recipient' not in message.keys():
            log(logging.ERROR, "No \"recipient id\" field in \"recipientPublicKey\" message: " + json.dumps(data))
            self.sendErrorMessage(client,"wrong message format", message['msg_id'], type="hmac")
            return

        if 'hmac' not in data.keys():
            log(logging.ERROR, "No \"hmac\" field in \"recipientPublicKey\" message: " + json.dumps(data))
            self.sendErrorMessage(client,"wrong message format", message['msg_id'], type="hmac")
            return

        client_hmac = base64.b64decode(data['hmac'])

        recipient_id = message['recipient']

        public = self.registry.getRecipientPubPkey(recipient_id)
        
        if(public):
            if(public==-1):
                self.sendErrorMessage(client,"User has no associated public key!", message['msg_id'], type="hmac") 
                return
            pub_key = public[0]
            pub_key_sign = public[1]
        else:
            self.sendErrorMessage(client,"User does not exist!", message['msg_id'], type="hmac")
            return

        certificate = self.registry.getRecipientCertificate(recipient_id)

        if(certificate):
            if(certificate==-1):
                self.sendErrorMessage(client,"User has no associated public key certificate!", message['msg_id'], type="hmac") 
                return
        else:
            self.sendErrorMessage(client,"User does not exist!", message['msg_id'], type="hmac") 
            return

        cert = certificate[0]
        cert_sign = certificate[1]

        msg={}
        msg['type'] = "recipient_pk"
        msg['msg_id'] = message['msg_id']
        msg['public_key'] = pub_key
        msg['public_key_signature'] = pub_key_sign
        msg['public_key_certificate'] = cert
        msg['certificate_signature'] = cert_sign

        print("PUBLIC KEY SIGNATURE %s" % pub_key_sign)

        hmac = generateHMAC(client.session_key,str(json.dumps(msg))) 

        client.sendResult({"message":json.dumps(msg),"hmac":base64.b64encode(hmac)})