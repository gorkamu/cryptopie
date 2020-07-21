#!/usr/local/bin python
#_*_ coding: utf8 _*_

import argparse
import os
import time
from os import system
from cryptography.fernet import Fernet


def banner():
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
	parser = argparse.ArgumentParser(description='List the content of a folder')	
	parser.add_argument('-p', '--path', type=str, required=True, help="define the file or directory path to encrypt/decrypt")
	parser.add_argument('-k', '--key', type=str, required=False, help="key to encrypt/decrypt. If it's not specified it be autogenerated")
	parser.add_argument('-e', '--encrypt', action='store_true', help="encrypt the file or directory")
	parser.add_argument('-d', '--decrypt', action='store_true', help="decrypt the file or directory")

	args = parser.parse_args()

	if args.encrypt == False and args.decrypt == False:
		print(" \033[31m[+] Error: \033[37m You have to specify which operation want to perform (encrypt/decrypt)\n")
		exit()

	op = "Encryption" if args.encrypt else "Decryption"

	if args.path:
		print("\033[36m[+] Path: \033[37m{}".format(args.path))		

	if args.key:
		print("\033[36m[+] {} key: \033[37m{}".format(op, args.key))
	else:
		args.key = Fernet.generate_key()
		print("\033[36m[+] {} key: \033[37m{}".format(op, args.key))	

	return args	


def perform(args):
	if args.encrypt:
		print("\033[32m[+] Encrypting:\033[37m")
		encrypt(args)
	elif args.decrypt:
		print("\033[32m[+] Decrypting:\033[37m")
		decrypt(args)	
	else:
		print(" \033[31m[+] Error: \033[37m No operation to perform\n")
		exit()
			

def encrypt(args, _file = None):	
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
	else:
		path_traverse(args)


def decrypt(args, _file = None):
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
	else:
		path_traverse(args)


def path_traverse(args):
	for item in os.listdir(args.path):
		_file = args.path + item

		if args.encrypt:
			print("\033[37m   {}{}".format(args.path, item))
			encrypt(args, _file)
		elif args.decrypt:
			print("\033[37m   {}{}".format(args.path, item))
			decrypt(args, _file)

		time.sleep(0.3)



def main():
	banner()
	perform(arg_parser())


if __name__ == '__main__':
	main()


