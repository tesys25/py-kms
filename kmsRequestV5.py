import aes
import binascii
import hashlib
import random
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
			('padding',      ':'),
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
		encrypted = bytearray(bytes(request['message']))
		iv = bytearray(request['message']['salt'])

		moo = aes.AESModeOfOperation()
		moo.aes.v6 = self.v6
		decrypted = moo.decrypt(encrypted, 256, moo.modeOfOperation["CBC"], self.key, moo.aes.keySize["SIZE_128"], iv)
		decrypted = aes.strip_PKCS7_padding(decrypted)

		return self.DecryptedRequest(decrypted)

	def encryptResponse(self, request, decrypted, response):
		randomSalt = self.getRandomSalt()
		result = hashlib.sha256(randomSalt).digest()

		iv = bytearray(request['message']['salt'])

		randomStuff = bytearray(16)
		for i in range(0,16):
			randomStuff[i] = (bytearray(decrypted['salt'])[i] ^ iv[i] ^ randomSalt[i]) & 0xff

		responsedata = self.DecryptedResponse()
		responsedata['response'] = response
		responsedata['keys'] = bytes(randomStuff)
		responsedata['hash'] = result
		
		padded = aes.append_PKCS7_padding(bytes(responsedata))
		moo = aes.AESModeOfOperation()
		moo.aes.v6 = self.v6
		mode, orig_len, crypted = moo.encrypt(padded, moo.modeOfOperation["CBC"], self.key, moo.aes.keySize["SIZE_128"], iv)

		return bytes(iv), bytes(bytearray(crypted))

	def decryptResponse(self, response):
		paddingLength = len(self.getResponsePadding(response['bodyLength1']))
		iv = bytearray(response['salt'])
		encrypted = bytearray(response['encrypted'][:-paddingLength])

		moo = aes.AESModeOfOperation()
		moo.aes.v6 = self.v6
		decrypted = moo.decrypt(encrypted, 256, moo.modeOfOperation["CBC"], self.key, moo.aes.keySize["SIZE_128"], iv)
		decrypted = aes.strip_PKCS7_padding(decrypted)

		return self.DecryptedResponse(decrypted)
		
	def getRandomSalt(self):
		return bytearray(random.getrandbits(8) for i in range(16))
	
	def generateResponse(self, iv, encryptedResponse, requestData):
		bodyLength = 4 + len(iv) + len(encryptedResponse)
		response = self.ResponseV5()
		response['versionMinor'] = requestData['versionMinor']
		response['versionMajor'] = requestData['versionMajor']
		response['salt'] = iv
		response['encrypted'] = encryptedResponse
		response['padding'] = self.getResponsePadding(bodyLength)

		if self.config['debug']:
			print("KMS V%d Response: %s" % (self.ver, response.dump()))
			print("KMS V%d Structue Bytes: %s" % (self.ver, binascii.b2a_hex(bytes(response))))

		return response

	def generateRequest(self, requestBase):
		esalt = self.getRandomSalt()

		moo = aes.AESModeOfOperation()
		moo.aes.v6 = self.v6
		dsalt = moo.decrypt(esalt, 16, moo.modeOfOperation["CBC"], self.key, moo.aes.keySize["SIZE_128"], esalt)
		dsalt = bytearray(dsalt)

		decrypted = self.DecryptedRequest()
		decrypted['salt'] = bytes(dsalt)
		decrypted['request'] = requestBase

		padded = aes.append_PKCS7_padding(bytes(decrypted))
		mode, orig_len, crypted = moo.encrypt(padded, moo.modeOfOperation["CBC"], self.key, moo.aes.keySize["SIZE_128"], esalt)

		message = self.RequestV5.Message(bytes(bytearray(crypted)))

		request = self.RequestV5()
		request['versionMinor'] = requestBase['versionMinor']
		request['versionMajor'] = requestBase['versionMajor']
		request['message'] = message

		if self.config['debug']:
			print("Request V%d Data: %s" % (self.ver, request.dump()))
			print("Request V%d: %s" % (self.ver, binascii.b2a_hex(bytes(request))))

		return request
