import os
import binascii
import hashlib
import pyaes
from kmsBase import kmsRequestStruct, kmsResponseStruct, kmsBase
from structure import Structure

class kmsRequestV5(kmsBase):
	class RequestV5(Structure):
		class Message(Structure):
			commonHdr = ()
			structure = (
				('salt',      '16s'),
				('encrypted', '236s'), #kmsRequestStruct
				('padding',   ':'),
			)

		commonHdr = ()
		structure = (
			('bodyLength1',  '<I=2 + 2 + len(message)'),
			('bodyLength2',  '<I=2 + 2 + len(message)'),
			('versionMinor', '<H'),
			('versionMajor', '<H'),
			('message',      ':', Message),
		)

	class DecryptedRequest(Structure):
		commonHdr = ()
		structure = (
			('salt',    '16s'),
			('request', ':', kmsRequestStruct),
		)

	class ResponseV5(Structure):
		commonHdr = ()
		structure = (
			('bodyLength1',  '<I=2 + 2 + len(salt) + len(encrypted)'),
			('unknown',      '!I=0x00000200'),
			('bodyLength2',  '<I=2 + 2 + len(salt) + len(encrypted)'),
			('versionMinor', '<H'),
			('versionMajor', '<H'),
			('salt',         '16s'),
			('encrypted',    ':'), #DecryptedResponse
			('padding',      ':=bytearray(4 + (((~bodyLength1 & 3) + 1) & 3))'),  # https://forums.mydigitallife.info/threads/71213-Source-C-KMS-Server-from-Microsoft-Toolkit?p=1277542&viewfull=1#post1277542
		)

	class DecryptedResponse(Structure):
		commonHdr = ()
		structure = (
			('response', ':', kmsResponseStruct),
			('keys',     '16s'),
			('hash',     '32s'),
		)

	key = bytearray([ 0xCD, 0x7E, 0x79, 0x6F, 0x2A, 0xB2, 0x5D, 0xCB, 0x55, 0xFF, 0xC8, 0xEF, 0x83, 0x64, 0xC4, 0x70 ])

	v6 = False

	ver = 5

	def executeRequestLogic(self):
		requestData = self.RequestV5(self.data)
	
		decrypted = self.decryptRequest(requestData)

		responseBuffer = self.serverLogic(decrypted['request'])
	
		iv, encrypted = self.encryptResponse(requestData, decrypted, responseBuffer)

		return self.generateResponse(iv, encrypted, requestData)
	
	def decryptRequest(self, request):
		encrypted = bytes(request['message'])
		iv = request['message']['salt']

		decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(self.key, iv, v6=self.v6))
		decrypted = decrypter.feed(encrypted) + decrypter.feed()

		return self.DecryptedRequest(decrypted)

	def encryptResponse(self, request, decrypted, response):
		randomSalt = bytearray(os.urandom(16))
		result = hashlib.sha256(randomSalt).digest()

		iv = bytearray(request['message']['salt'])

		randomStuff = bytearray(16)
		for i in range(0,16):
			randomStuff[i] = (bytearray(decrypted['salt'])[i] ^ iv[i] ^ randomSalt[i]) & 0xff

		responsedata = self.DecryptedResponse()
		responsedata['response'] = response
		responsedata['keys'] = bytes(randomStuff)
		responsedata['hash'] = result

		encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(self.key, iv, v6=self.v6))
		crypted = encrypter.feed(responsedata) + encrypter.feed()

		return bytes(iv), crypted

	def decryptResponse(self, response):
		paddingLength = len(response.packField('padding'))
		iv = response['salt']
		encrypted = response['encrypted'][:-paddingLength]

		decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(self.key, iv, v6=self.v6))
		decrypted = decrypter.feed(encrypted) + decrypter.feed()

		return self.DecryptedResponse(decrypted)
	
	def generateResponse(self, iv, encryptedResponse, requestData):
		response = self.ResponseV5()
		response['versionMinor'] = requestData['versionMinor']
		response['versionMajor'] = requestData['versionMajor']
		response['salt'] = iv
		response['encrypted'] = encryptedResponse

		if self.config['debug']:
			print("KMS V%d Response: %s" % (self.ver, response.dump()))
			print("KMS V%d Structue Bytes: %s" % (self.ver, binascii.b2a_hex(bytes(response))))

		return response

	def generateRequest(self, requestBase):
		esalt = bytearray(os.urandom(16))

		dsalt = pyaes.AESModeOfOperationCBC(self.key, iv=esalt, v6=self.v6).decrypt(esalt)

		decrypted = self.DecryptedRequest()
		decrypted['salt'] = dsalt
		decrypted['request'] = requestBase

		encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(self.key, esalt, v6=self.v6))
		crypted = encrypter.feed(decrypted) + encrypter.feed()

		message = self.RequestV5.Message(crypted)

		request = self.RequestV5()
		request['versionMinor'] = requestBase['versionMinor']
		request['versionMajor'] = requestBase['versionMajor']
		request['message'] = message

		if self.config['debug']:
			print("Request V%d Data: %s" % (self.ver, request.dump()))
			print("Request V%d: %s" % (self.ver, binascii.b2a_hex(bytes(request))))

		return request
