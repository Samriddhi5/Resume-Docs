#!/usr/bin/python3

import optparse, subprocess, pwd, grp, os, platform
from socket import *
from threading import Thread
import netifaces as ni  # a library that displays network's interface info
import tabulate, psutil
from cryptography.fernet import Fernet # a library for encryption

def hostnamefunc(): # this function displays all the details about the hostname
	hostName=gethostname()
	IP_add=gethostbyname(hostName)
	OS=platform.system()
	sysdata=platform.platform()
	sys_name=platform.uname()
	processorname=sys_name.processor
	print("Static hostname: " + hostName)
	print("IP Address: " + IP_add)
	print("Version: " + (sys_name.version))
	print("Machine: "+  (sys_name.machine))
	print("System: " + (sys_name.system))
	print("OS(Operating System): " + OS)
	print("Architecture: " + processorname)
	print ("Other Details: " + sysdata)

def main(): #defining the main func with all the necessary info for the user to run the admino script
    help_info = """
        Welcome to the Admino system information script
        Please follow the following instructions to use it

        - admino -H --> provides hostname information.
        - admino -i <interface> --> provides the IP address of provided <interface>
        - admino -u --> provides the list of users of the system.
        - admino -g <groupname> --> provides the list of users for an specific <group>
        - admino -t <user> --> provides the directory list tree for a system <user>
        - admino -l --> provides the list of IPs from last remote connections.
        - admino -p --> provides the top 10 processes which are using more %memory
        - admino -s --> provides the list of SUDO invoked commands from auth.log
        - admino -d <filename> --> Encrypt and Decrypt files using Python <filename>.
        """
    parser = optparse.OptionParser(usage=help_info, version="%prog")
    parser.add_option('-H', action="store_true", dest="hostnamevar",
      help='Hostname Information')
    parser.add_option('-i', dest='interfacevar', type='string',\
      help='provide IP Address of provided <interface>')
    parser.add_option('-u', action="store_true", dest="usersvar",
      help='List of users of the system')
    parser.add_option('-g', dest='groupvar', type='string',\
      help='List of users belonging to the specified group')
    parser.add_option('-t', dest='treevar', type='string',\
      help='directory list tree for the specified user')
    parser.add_option('-l', dest="ipvariable", type = 'string',\
      help='List of IPs from last remote connections')
    parser.add_option('-p', action="store_true", dest="processvar",
      help='List of top 10 processes which are using more memory')
    parser.add_option('-s', action="store_true", dest="sudovar",
      help='List of SUDO invoked commands from auth.log')
    parser.add_option('-d', dest="filenamevar", type ='string',\
      help='Encrypt and Decrypt files using Python <filename>')

    (options, args) = parser.parse_args()
    hostnamevar=options.hostnamevar
    interfacevar=options.interfacevar
    usersvar=options.usersvar
    groupvar=options.groupvar
    treevar=options.treevar
    ipvariable=options.ipvariable
    processvar=options.processvar
    sudovar=options.sudovar
    filenamevar=options.filenamevar

    if (hostnamevar==True):
        hostnamefunc()
        exit(0)

    if (interfacevar!= None):
        IPinterfacefunc(interfacevar)
        exit(0)
		
    if (usersvar==True):
        usersfunc()
        exit(0)

    if (groupvar!= None):
        groupfunc(groupvar)
        exit(0)

    if (treevar != None):
        treefunc(treevar)
        exit(0)

    if (ipvariable!=None):
        remotecmmdfunc(ipvariable)
        exit(0)

    if (processvar==True):
        processfunc()
        exit(0)

    if (sudovar==True):
        sudofunc()

    if (filenamevar!=None):
        encryptdecrypt_func(filenamevar)
        exit(0)

    print(parser.usage)

def IPinterfacefunc(interfacevar): #this function provides the IP address of the interface
	try:
		ip = ni.ifaddresses(interfacevar)[ni.AF_INET][0]['addr']
		print ("IP address for " + interfacevar + " interface is :" + ip)
	except:
		print("No interface named : " + interfacevar + " exists. Please try again with a correct interface name.")

def treefunc(treevar): #this function provides the directory in a tree hierarchy
    startpath="/home/" + treevar
    for root, dirs, files in os.walk(startpath):
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * (level)
        print('{}{}/'.format(indent, os.path.basename(root)))
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            print('{}{}'.format(subindent, f))

def groupfunc(groupvar): #this function list the users of a specific group
	try:
		members=grp.getgrnam(groupvar)
		grpusers=members[3]
		if not grpusers:
			print ("There are currently no users in the group: " + groupvar)
		else:
			print ("The list of users belonging to the group -" + groupvar + " are: ")
			for users in range(len(grpusers)):
				print ("   -  " + grpusers[users])
	except:
		print ("No group called " + groupvar + " exists in the system.")

def remotecmmdfunc(ip):
    ips = []
    try:
        result = subprocess.run(['tail', '-n', '20', '/var/log/auth.log'], capture_output=True, text=True)
        ips = [line.split()[-3] for line in result.stdout.splitlines() if 'sshd' in line]
        
        if ips:
            print("List of IPs from last remote connections:")
            for ip in ips:
                print(f"    - {ip}")
        else:
            print("No IPs found!")
    except:
        pass

def processfunc(): #function which list the top 10 processes with high memory in descending order
	processlist=[]
	print("The list of top 10 processes which are using more %memory :")
	for i in psutil.process_iter():
		try:
			pinfo=i.as_dict(attrs=['pid','name','username','cpu_percent', 'memory_percent'])
			pinfo['memory usage'] = i.memory_info().vms / (1024*1024)
			processlist.append(pinfo)
		except:
			pass

	processlist=sorted(processlist, key=lambda procObj: procObj['memory_percent'], reverse =True)
	dataset=processlist[:10]
	header = dataset[0].keys()
	rows =  [x.values() for x in dataset]
	print(tabulate.tabulate(rows, header, tablefmt='grid'))

def sudofunc():
    try:
        result = subprocess.run(['grep', 'sudo.*COMMAND', '/var/log/auth.log'], stdout=subprocess.PIPE, check=True)
        lines = result.stdout.decode('utf-8').splitlines()
        
        for line in lines:
            parts = line.split()
            
            if len(parts) >= 3:
                timestamp = ' '.join(parts[:3])
                command_part = line.split("COMMAND=")[1].strip()
                print(f"Date: {timestamp}\t SUDO COMMAND={command_part}")
    
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr.decode('utf-8')}")

def Encryptfunc(initial, key): # function for encrypting a file with user's key
	f=Fernet(key)
	encrypted=f.encrypt(initial)
	with open('encryptedfile.txt', 'wb') as encrypted_file:
		encrypted_file.write(encrypted)
	print("File encrypted successfully!: Encrypted file has been created")

def Decryptfunc(initial, key): # function for decrpyting a file with user's key
	f=Fernet(key)
	decrypted=f.decrypt(initial)
	with open('decryptedfile.txt', 'wb') as decrypted_file:
		decrypted_file.write(decrypted)
	print("File decrypted successfully!: Decrypted file has been created")

def encryptdecrypt_func(filenamevar):
	try:
		with open(filenamevar, 'rb') as initial_file:
			initial=initial_file.read()

		task=input("For Encryption press 'e' or 'E' \nFor Decryption press 'd' or 'D'\nEnter your choice : ")
		if (task=="e") | (task=="E"):
			response1=input("Do you have an existing key file? If yes, please enter the filename else press 'n' for NO : ")
			if (response1=="n"):
				key = Fernet.generate_key()
				print ("A new key file will be created")
				with open('samriddhi.pub', 'wb') as samriddhikey:
					samriddhikey.write(key)
				Encryptfunc(initial, key)
			else:
				print("Existing key file to be used")
				try:
					with open(str(response1), 'rb') as samriddhikey:
						key=samriddhikey.read()
					Encryptfunc(initial, key)
				except:
					print("No such key file exists in the directory")

		elif (task=="d") | (task=="D"):
			try:
				keyfile=input("Please enter the existing key filename: ")
				with open(str(keyfile), 'rb') as samriddhikey:
					key=samriddhikey.read()
				Decryptfunc(initial, key)
			except:
				print("No such Key file exists in the directory.")
		else:
			print("Please type the correct option 'e'/'E' or 'd'/'D'")
			encryptdecrypt_func(filenamevar)

	except:
		print("The filename that you have entered for Encryption or Decryption doesn't exist in this directory. Please try again with a correct filename.")

def usersfunc(): # this func gives the list of users of the system
	print ("The list of users of your system are:")
	for user in pwd.getpwall():
		print("    - "+ user[0])

if __name__ == '__main__':
    main()