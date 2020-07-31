#!/usr/local/bin python
#_*_ coding: utf8 _*_

import argparse
import os
import time
import base64
import random
import string
from os import system
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def banner():
	"""Print the tool banner
    
    """			
	system("clear")
	print("""
 \033[33m▄████▄   ██▀███ \033[31m▓\033[33m██   ██\033[31m▓ \033[33m██\033[31m▓\033[33m███  ▄▄▄█████\033[31m▓ \033[31m▒\033[33m█████  
\033[31m▒\033[33m██▀ ▀█  \033[31m▓\033[33m██ \033[31m▒ \033[33m██\033[31m▒▒\033[33m██  \033[33m██\033[31m▒▓\033[33m██\033[31m░  \033[33m██\033[31m▒▓  \033[33m██\033[31m▒ ▓▒▒\033[33m██\033[31m▒  \033[33m██\033[31m▒
\033[31m▒▓\033[33m█    ▄ \033[31m▓\033[33m██ \033[31m░\033[33m▄█ \033[31m▒ ▒\033[33m██ ██\033[31m░▓\033[33m██\033[31m░ \033[33m██\033[31m▓▒▒ ▓\033[33m██\033[31m░ ▒░▒\033[33m██\033[31m░  \033[33m██\033[31m▒
\033[31m▒▓▓\033[33m▄ ▄██\033[31m▒▒\033[33m██▀▀█▄   \033[31m░ \033[33m▐██\033[31m▓░▒\033[33m██▄█\033[31m▓▒ ▒░ ▓\033[33m██\033[31m▓ ░ ▒\033[33m██   ██\033[31m░
\033[31m▒ ▓\033[33m███▀ \033[31m░░\033[33m██\033[31m▓ ▒\033[33m██\033[31m▒ ░ \033[33m██\033[31m▒▓░▒\033[33m██\033[31m▒ ░  ░  ▒\033[33m██\033[31m▒ ░ ░ \033[33m████\033[31m▓▒░
\033[31m░ ░▒ ▒  ░░ ▒▓ ░▒▓░  \033[33m██\033[31m▒▒▒ ▒▓▒░ ░  ░  ▒ ░░   ░ \033[31m▒░▒░▒░ 
  \033[31m░  ▒     ░▒ ░ ▒░▓\033[33m██\033[31m ░▒░ ░▒ ░         ░      ░ ▒ ▒░ 
\033[31m░          ░░   ░ ▒ ▒ ░░  ░░         ░      ░ ░ ░ ▒  
\033[31m░ ░         ░     ░ ░                           ░ ░  
\033[31m░                 ░ ░                                
                \033[36m██\033[35m▓\033[36m███   ██\033[35m▓▓\033[36m█████                   
               \033[35m▓\033[36m██\033[35m░  \033[36m██\033[35m▒▓\033[36m██\033[35m▒▓\033[36m█   ▀                   
               \033[35m▓\033[36m██\033[35m░ \033[36m██\033[35m▓▒▒\033[36m██\033[35m▒▒\033[36m███                     
               \033[35m▒\033[36m██▄█\033[35m▓▒ ▒░\033[36m██\033[35m░▒▓\033[36m█  ▄                   
               \033[35m▒\033[36m██\033[35m▒ ░  ░░\033[36m██\033[35m░░▒\033[36m████\033[35m▒                  
               \033[35m▒▓▒░ ░  ░░▓  ░░ ▒░ ░                  
               \033[35m░▒ ░      ▒ ░ ░ ░  ░                  
               \033[35m░░        ▒ ░   ░                     
               \033[35m          ░     ░  ░   

 \033[36m------[ \033[33mCryptoPie v.1.0. - By okBoomer 2020 \033[36m]------\n\033[37m
		""")


def arg_parser():
	"""Parse the arguments
    
    """		
	parser = argparse.ArgumentParser(description='Encrypt or decrypt just a file or an entire path using different algorithms')	
	parser.add_argument('-p', '--path', type=str, required=True, action='store', help="define the file or directory path to encrypt/decrypt")
	parser.add_argument('-k', '--key', type=str, required=False, action='store', help="key to encrypt/decrypt")
	parser.add_argument('-e', '--encrypt', action='store_true', help="encrypt the file or directory")
	parser.add_argument('-d', '--decrypt', action='store_true', help="decrypt the file or directory")
	parser.add_argument('-a', '--algorithm', action='store', help="encryption algorithm: [SHA224|SHA256|SHA384|SHA512|SHA512_224|SHA512_256|BLAKE2b|BLAKE2s|SHA3_224|SHA3_256|SHA3_384|SHA3_512|SHAKE128|SHAKE256|SHA1|MD5]")


	args = parser.parse_args()

	if args.encrypt == False and args.decrypt == False:
		print(" \033[31m[+] Error: \033[37m You have to specify which operation want to perform (encrypt/decrypt)\n")
		exit()

	op = "Encryption" if args.encrypt else "Decryption"

	if args.path:
		print("\033[36m[+] Path: \033[37m{}".format(args.path))		

	if args.key and args.decrypt:
		print("\033[36m[+] {} key: \033[37m{}".format(op, args.key))
	elif args.key is None and args.encrypt:
		args.key = generate_key(args.algorithm)
		print("\033[36m[+] {} key: \033[37m{}".format(op, args.key))
		print("\033[36m[+] Algorithm: \033[37m{}".format(args.algorithm))
	else:
		print("\033[31m[+] Error: \033[37m key should only be specified in the decryption operation\n")
		exit()

	return args	

def generate_key(algorithm):
	"""Generate encryption key
    
    """		
	backend = default_backend()
	salt = os.urandom(16)
	kdf = PBKDF2HMAC(
		algorithm = get_algorithm(algorithm),
		length = 32,
		salt = salt,
		iterations = 1000,
		backend = backend
	)

	key = base64.urlsafe_b64encode(kdf.derive(get_random_password_string(32)))

	return key

def get_algorithm(algorithm):
	"""Get encryption algorithm
    
    """
	algo = hashes.SHA256()
	algorithms = ["SHA224", "SHA256", "SHA384", "SHA512", "SHA512_224", "SHA512_256", "BLAKE2b", "BLAKE2s", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512", "SHAKE128", "SHAKE256", "SHA1", "MD5"]

	if algorithm is not None and algorithm in algorithms:
		algo = getattr(hashes, algorithm)

	return algo

def get_random_password_string(length):
	"""Generate random string
    
    Arguments:
    length -- string length

    """		
	password_characters = string.ascii_letters + string.digits + string.punctuation
	return ''.join(random.choice(password_characters) for i in range(length))
			

def encrypt(args, _file = None):
	"""Encrypt the passed file
  
    Arguments:
    args -- object with the parsed arguments
    _file -- file to encrypt
    
    """		
	f = Fernet(args.key)

	if _file is not None:
		efile = _file
	else:
		efile = args.path

	if os.path.isfile(efile):
		with open(efile, 'rb') as file:
			file_data = file.read()

		encrypted_data = f.encrypt(file_data)

		with open(efile, 'wb') as file:
			file.write(encrypted_data)

		print("\033[37m   {}".format(efile))	


def decrypt(args, _file = None):
	"""Decrypt the passed file
  
    Arguments:
    args -- object with the parsed arguments
    _file -- file to decrypt
    
    """	
	try:
		f = Fernet(args.key)

		if _file is not None:
			dfile = _file
		else:
			dfile = args.path

		if os.path.isfile(dfile):
			with open(dfile, 'rb') as file:
				file_data = file.read()

			decrypted_data = f.decrypt(file_data)

		  	with open(dfile, "wb") as file:
				file.write(decrypted_data)

			print("\033[37m   {}".format(dfile))

	except Exception as e:
		print("\033[31m[+] Error: \033[37m Wrong decrypting key\n")
		exit()


def perform(args):
	"""Performs the encryption/decryption operation over a single file or over a directory structure recursively
  
    Arguments:
    args -- object with the parsed arguments
    
    """	
	if os.path.isfile(args.path):
		if args.encrypt:
			print("\033[32m[+] Encrypting:\033[37m")
			encrypt(args)
		elif args.decrypt:
			print("\033[32m[+] Decrypting:\033[37m")
			decrypt(args)	
		else:
			print(" \033[31m[+] Error: \033[37m No operation to perform\n")
			exit()
	elif os.path.isdir(args.path):	
		files = []
		for r, d, f in os.walk(args.path):
		    for file in f:
		    	fi = os.path.join(r, file)
		    	if os.path.isfile(fi) and file != '.DS_Store':
		        	files.append(fi)	   

		if args.encrypt:
			print("\033[32m[+] Encrypting:\033[37m")
		elif args.decrypt:
			print("\033[32m[+] Decrypting:\033[37m")

		for f in files:
			if args.encrypt:
				encrypt(args, f)
			elif args.decrypt:
				decrypt(args, f)

		time.sleep(0.3)
	else:
		print("\033[31m[+] Error: \033[37m Path doesn't exists\n")
		exit()


def main():
	banner()
	perform(arg_parser())

	

if __name__ == '__main__':
	main()


