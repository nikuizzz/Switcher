# IMPORTS
from pprint import *
import re
import telnetlib
import getpass
import sys
import os
import shutil
import tkinter as tk
from tkinter import filedialog
import json
import time
import serial
import serial.tools.list_ports
import bcrypt
# END IMPORTS

#COLORS
color = ""
while color.lower() not in ["o", "n"]:
    color = str(input("Utiliser des couleurs? ( O/n ) -> ")).lower()

if color == "o":
    CEND = '\033[0m'
    CURL = '\033[4m'
    CBLINK = '\033[6m'
    CRED = '\033[91m'
    CDARKGREEN = '\033[32m'
    CGREEN = '\033[92m'
    CYELLOW = '\033[93m'
    CBLUE = '\033[94m'
    CPINK = '\033[95m'
    CBEIGE = '\033[96m'
else:
    CEND,CURL,CBLINK,CRED,CDARKGREEN,CGREEN,CYELLOW,CBLUE,CPINK = ["" for i in range(9)]
# END COLORS

class SwitcherUtils:
    '''
    Proposes several utilities for the Switcher class.
    '''
    @staticmethod
    def start():
        print(f"{CDARKGREEN}[{CEND}¤{CDARKGREEN}] Début du script...{CEND}")
        
    @staticmethod
    def end():
        print(f"{CDARKGREEN}[{CEND}¤{CDARKGREEN}] Fin du script...{CEND}")

    @staticmethod
    def ask_script() -> str:
        '''
        Asks for user input ( pull / push / generate / detail ) to specify the type of script.
        Used in Switcher constructor to initialise self.script
        '''
        script = str(input(f"{CYELLOW}Choisissez la fonctionnalité que vous voulez utiliser ( {CEND}pull{CYELLOW} / {CEND}push{CYELLOW} / {CEND}generate{CYELLOW} / {CEND}detail{CYELLOW} ) -> {CEND}"))
        tries = 0
        while script not in ["pull", "push", "generate", "detail"]:
            if tries == 2:
                sys.exit(0)
            script = str(input(f"{CRED}Vous devez choisir parmis les fonctionnalités suivates: {CEND}pull{CRED} / {CEND}push{CRED} / {CEND}generate{CRED} / {CEND}detail{CRED} -> {CEND}"))
            tries += 1
        return script
    
    @staticmethod
    def ask_configuration_type() -> str:
        '''
        Asks for user input ( local/telnet ).
        Used in Switcher constructor to initialise self.configuration_type
        '''
        configuration_type = ""
        while configuration_type not in ["local", "telnet"]:
            configuration_type = str(input(f"\n{CYELLOW}Choisissez le type de configuration ( {CEND}local{CYELLOW} / {CEND}telnet{CYELLOW} ) -> {CEND}"))
            if configuration_type not in ["local", "telnet"]:
                print(f"{CRED}Entrée invalide. Reessayez.{CEND}")

        return configuration_type

    @staticmethod
    def ask_configuration_file(configuration_type) -> str:
        '''
        If configuration_type is local:
            Asks user to choose a local configuration file, which then will be analysed.
            If user closes the window twice, the script stops.
        If configuration_type is telnet:
            Defines the path of the extrated configuration file, './bin/last-extracted-config'.
            Later, the configuration extracted via telnet will be copied to this file.
        '''
        path = ""
        if configuration_type == "local":
            i = 0
            while True:
                if i >= 2:
                    sys.exit(0)
                path = filedialog.askopenfilename()
                if os.path.isfile(path):
                    try:
                        with open(path, "r"):
                            pass
                        break
                    except IOError:
                        print(f"{CRED}ERROR -> {CEND}{path}{CRED} ne peut pas être lu.{CEND}")
                else:
                    print(f"{CRED}ERROR -> {CEND}{path}{CRED} fichier n'est pas un fichier valide.{CEND}")
                    i += 1
                    
        else:
            path = "./bin/last-extracted-config.txt"

        return path
    
    @staticmethod
    def get_ip_address(address: str, return_bool=False) -> str:
        '''
        Takes an IP address as parameter. 
        If address is valid, the address is returned. 
        If address is invalid, asks for user input until it gets a valid address
        '''
        if return_bool:
            validate = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", address)
            return bool(validate)
        
        if address == "":
            address = str(input(f"{CYELLOW}Adresse IP du Switch -> {CEND}"))
        validate = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", address)

        while bool(validate) is False:
            address = str(input(f"{CRED}Adresse IP invalide. Reesayez -> {CEND}"))
            validate = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", address)

        return address
    
    @staticmethod
    def get_numbers(interval: str) -> str:
        '''
        First case:
            Takes a string of ports ( 1-3 ) as parameter
            and returns a converted string ( 1,2,3 )
        Second case:
            Takes a string of ports ( 1,2,3 ) as parameter
            and returns a converted string ( 1-3 )
        '''
        result = []
        if "-" in interval:
            start = int(interval.split("-")[0])
            end = int(interval.split("-")[1])

            for i in range(start,end+1):
                result.append(f"{i}")
        elif "," in interval:
            interval = interval.split(',')
            result = f"{interval[0]}-{interval[-1]}"
        else:
            return None
        
        return result

    @staticmethod
    def filter_port(port: str) -> str:
        '''
        Filters ports, converts all types of input to a single type output
        '''
        result = ""
        # When port = 1, 45, 23 etc...
        if "/" not in port and "-" not in port:
            result += f"1/{port},"

        # When port = 1/2, 1/5, 2/23 etc...
        elif "/" in port and "-" not in port:
            result += f"{port},"
        
        # When port = 1-3, 12-14, 35-48 etc... 
        elif "/" not in port and "-" in port:
            for number in SwitcherUtils.get_numbers(port):
                result += f"1/{number},"

        # When port = 1/2-4, 2/13-14, 2/20-34
        else:
            temp = port.split("/")
            for number in SwitcherUtils.get_numbers(temp[1]):
                result += f"{temp[0]}/{number},"

        return result[:-1]
    
    @staticmethod
    def get_ports(ports: str) -> str:
        '''
        First case:
            Takes a string of ports ( 1/2-3,2/34-35 ) as parameter
            and returns a converted string ( 1/2,1/3,2/34,2/35 )
        Second case:
            Takes a string of ports ( 1/1,1/2,1/36,1/38 ) as parameter
            and returns a converted string ( 1/1-3,1/36-38 )
        '''
        result = ""
        if "-" not in ports and "," not in ports:
            if "/" not in ports and ports != "NONE":
                ports = f"1/{ports}"
            return ports

        if "," in ports:
            for port in ports.split(","):
                result += f"{SwitcherUtils.filter_port(port)},"
        else:
            result += f"{SwitcherUtils.filter_port(ports)},"

        return result[:-1]
    
    @staticmethod
    def check_login(user: str, password: str) -> bool:
        '''
        Checks if the given user and password are correct.
        Return a tuple with 3 elements:
        1 -> A boolean that specifies wether the connection is valid or unvalid ( True, False )
        2 -> An integer specifiying the type of return
            1: Valid login
            2: Wrong password
            3: User does not exist
        3 -> A string specifiying the error.

        This method required the bcrypt library to be installed.
        If bcrypt is missing, it always returns False,
        '''
        with open('./bin/passwd.json', 'r') as file:
            data = json.load(file)
            for i in range(len(data.keys())):
                key = list(data.keys())[i]
                hashed_user = (bytes.fromhex(key)).decode('utf-8')
                if bcrypt.checkpw(user.encode('utf-8'),hashed_user.encode('utf-8')):
                    hashed_password = (bytes.fromhex(data[key])).decode('utf-8')
                    if bcrypt.checkpw(password.encode('utf-8'),hashed_password.encode('utf-8')):
                        return (True, 1, "Connected")
                    return (False, 2, "Le mot de passe que vous avez specifié n'est pas valide. Reessayez.")
                if i == len(data.keys())-1:
                    return (False, 3, "Le login que vous avez specifié n'est pas valide. Reessayez.")

    @staticmethod
    def add_password(user: str, password: str) -> None:
        '''
        Adds a new login an password to the passwd.json file.
        '''
        hashed_user = bcrypt.hashpw(user.encode('utf-8'), bcrypt.gensalt())
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        data = {}
        with open('./bin/passwd.json', 'r') as file:
            data = json.load(file)
            data[hashed_user.hex()] = hashed_password.hex()

        with open('./bin/passwd.json', 'w') as file:
            file.write(json.dumps(data, indent=4))

    @staticmethod
    def filter_conf(path: str) -> None:
        '''
        Filters a config file given in parameters.
        Removes unnecessary lines ( comments, blanks, etc... ).
        It also reconstructs lines that were split in 2, due to telnet characters limit.
        '''
        data = []
        with open(path, "r") as file:
            for line in file:
                if "mac-security" in line or "egressmap" in line or "rmon" in line or "igmp" in line or "ipmgr" in line or "mlt" in line or "adac" in line or "tacacs" in line or "eapol" in line or "vlacp" in line or "!" in line or "show run" in line:
                    continue
                if "\n" == line:
                    continue
                if "\x08" in line:
                    line = line.rsplit('\x08', 1)
                    line = line[1]
                    
                line = line.replace("\n", "")
                data.append(line)

        with open(path, "w") as file:
            skip_next_line = False
            for i in range(len(data)-1):
                if skip_next_line:
                    skip_next_line = not skip_next_line
                    continue
                line = data[i]
                if len(line) > 75:
                    skip_next_line = not skip_next_line
                    line = line + data[i+1]
                file.write(line + "\n")

    @staticmethod
    def get_com_port() -> tuple[bool, str]:
        '''
        Parameters:
        Description:
            Searches for available and connected COM ports.
            If a port is found, it returns -> ( True, "COMX" )
            If no ports are found, it returns -> ( False, "error description" )
        '''
        ports = serial.tools.list_ports.comports()
        for port, description, hwid in ports:
                if "Serial" in description:
                    return (True, port)
        return (False, f"{CRED}Il n'y a aucun port COM connecté. Reesayez.{CEND}")
    
    @staticmethod
    def send_serial(port: str, command: str) -> None:
        '''
        Parameters:
            port ( serial ) -> serial.Serial() object
            command ( str ) -> command to write
        Description:
            Pushes the given command to the switch via serial port
        '''
        command = command + "\r"
        port.write(command.encode('utf-8'))

    @staticmethod
    def get_serial(port: serial, length: int=200) -> str:
        '''
        Parameters:
            Port ( serial ) -> serial.SerialPort object
            length ( integer ) -> number of bytes to read, default value 200
        Description:
            Returns the output
        '''
        return port.read(length).decode('utf-8')

    @staticmethod
    def print_serial(port: serial, length: int=200) -> None:
        '''
        Parameters:
            port ( serial ) -> serial.Serial() object
            length ( integer ) -> number of bytes to read, default value 200
        Description:
            Prints the output
        '''
        print(SwitcherUtils.get_serial(port, length))

    @staticmethod
    def create_directory(script:str, name: str, ip: str) -> str:
        '''
        Parameters:
            script ( str ) -> type of the script ( pull, push, etc... )
            name ( str ) -> snmp-server name of the switch
            ip ( str ) -> IP address of the switch
        Description:
            Creates a new directory and copies the configuration file into it.
            Used every time that this script is used, to store different versions of the configiurations.

            Returns the path to the created directory.
        '''
        if name == "":
            dir_path = f"./configs/{script.upper()} - {ip} - v1"
        else:
            dir_path = f"./configs/{script.upper()} - {name} - {ip} - v1"

        while os.path.exists(dir_path):
            dir_path = dir_path.split("v")
            index = int(dir_path[-1]) + 1
            dir_path = f"{dir_path[0]}v{index}"
        os.mkdir(dir_path)

        # COPYING EXTRACTED CONFIG
        destination = f"{dir_path}/config.txt"
        shutil.copy2("./bin/last-extracted-config.txt", destination)

        # COPYING GENERATED CONFIG
        if script == "generate":
            destination = f"{dir_path}/generated-config.txt"
            shutil.copy2("./bin/last-generated-config.txt", destination)

        # COPYING GENERATED CONFIG + ICL
        elif script == "generate & detail":
            destination = f"{dir_path}/generated-config.txt"
            shutil.copy2("./bin/last-generated-config.txt", destination)

            destination = f"{dir_path}/info.json"
            shutil.copy2("./bin/last-extracted-icl.json", destination)

        # COPYING ICL
        elif script == "detail":
            destination = f"{dir_path}/info.json"
            shutil.copy2("./bin/last-extracted-icl.json", destination)

        return dir_path

class Switcher(SwitcherUtils):
    '''
    Ce script propose plusieures fonctionnalités afin de simplifier le deploiement et la configuration des nouveaux switch ERS 3600.
    Voici une liste de ces fonctionnalités: 

    1 -> pull
        Récuperer la configuration d'un switch via telnet
    2 -> push
        Pousser une configuration sur le switch via le câble console
    3 -> generate
        Générer une nouvelle configuration adaptée aux 3600
    4 -> detail
        Récuperer les informations importantes à partir d'un fichier de configuration

    © Ziuzin Nikita 
    '''
    def __init__(self, script="", configuration_type="", path="", ip="", user="", password="", include_suggestions="file", include_icl=True):
        self.root = tk.Tk()
        self.root.withdraw()

        self.icl = {
            "ip address||netmask": "",
            "ip default-gateway": "",
            "ip address netmask": "",
            "snmp-server name": "",
            "snmp-server location": "",
            "tagAll": [],
            "vlan create": [],
            "vlan name": [],
            "vlan members": [],
            "vlan ports": [],
            "vlan mgmt": "",
            "name port": []
        }
        self.site = ""

        self.ip = ip
        self.user = user
        self.password = password
        self.include_suggestions = include_suggestions
        self.include_icl = include_icl

        self.script = script
        if self.script not in ["pull", "push", "generate", "detail"]:
            print(self.__doc__)
            self.script = SwitcherUtils.ask_script()

        # PULL
        if self.script == "pull":
            print(f"{CPINK}\nVous êtes en mode {CEND}{self.script.upper()}{CPINK}. Pour récupérer la configuration via telnet, veuillez renseigner les informations suivantes: \n{CEND}")
            
            self.path = "./bin/last-extracted-config.txt"
            self.get_conf()

            self.path = self.create_directory(self.script, self.icl["snmp-server name"], self.ip)

            print(f"\n{CPINK}La configuration a été extraite dans le dossier {CEND}{self.path}{CPINK}.{CEND}\n")
        
        # PUSH
        elif self.script == "push":
            print(f"{CPINK}\nVous êtes en mode {CEND}{self.script.upper()}{CPINK}. Veuillez choisir le fichier de configuration à recopier sur le switch: \n{CEND}")
            
            self.configuration_type = "local"

            self.path = path
            if self.path == "":
                self.path = SwitcherUtils.ask_configuration_file(self.configuration_type)

            port_com = self.get_com_port()
            if port_com[0]:
                self.push_config(port_com[1])
                print(f"\n{CPINK}La configuration {CEND}{self.path}{CPINK} a été recopiée sur le switch.\n{CEND}")
            else:
                print(port_com[1])

        # GENERATE
        elif self.script == "generate" or self.script == "detail":
            print(f"\n{CPINK}Vous êtes en mode {CEND}{self.script.upper()}{CPINK}. Veuillez choisir comment vous voulez extraire la configuration:{CEND}")
            
            # GETTING CONFIGURATION TYPE ( LOCAL OR TELNET )
            self.configuration_type = configuration_type
            if self.configuration_type == "":
                self.configuration_type = SwitcherUtils.ask_configuration_type()

            # GETTING PATH VARIABLE 
            self.path = path
            if path == "":
                self.path = SwitcherUtils.ask_configuration_file(self.configuration_type)

            # Getting configuration from switch with telnet
            if self.configuration_type == "telnet":
                self.get_conf()

            # Extracting important command lines from the configuration
            self.extract_icl()

            # IF -> Generating new configuration
            
            if self.script == "generate":
                self.generate_config()
                if self.include_icl is True:
                    self.generate_icl()
                    self.script = "generate & detail"
                self.path = self.create_directory(self.script, self.icl["snmp-server name"], self.ip)
                print(f"\n{CPINK}La configuration générée a été sauvegardée dans le dossier {CEND}{self.path}{CEND}")
                print(f"{CPINK}Vous pouvez la vérifier puis la recopier directement sur le switch avec la fonctionnalité {CEND}PUSH{CPINK} de ce script.{CEND}\n")
                
                if self.include_suggestions is not None:
                    self.suggest()
            
            # ELIF -> Writing ICL to ./bin/icl.json
            elif self.script == "detail":
                self.generate_icl()
                self.path = self.create_directory(self.script, self.icl["snmp-server name"], self.ip)
                print(f"\n{CPINK}Les informations importantes ont étés extraites dans le dossier {CEND}{self.path}{CEND}\n")

    def get_conf(self) -> None:
        '''
        Retrieves the config of a switch via telnet.

        Takes multiple parameters :
        address -> Takes the IP address of the switch you want to access.
        user -> Takes the IP address of the switch you want to access.
        password -> Takes the IP address of the switch you want to access.

        If one of these parameters is not specified, it will be requested by user input. 
        '''
        try: 
            self.ip = SwitcherUtils.get_ip_address(self.ip)

            telnet = telnetlib.Telnet(self.ip, 23, 15)

            telnet.read_until(b"***",15)
            telnet.write("\x19 \n \t".encode('ascii'))
            telnet.read_until(b"***",15)

            while True:
                if self.user == "":
                    self.user = str(input(f"{CYELLOW}Login -> {CEND}"))
                if self.password == "":
                    self.password = getpass.getpass(f"{CYELLOW}Mot de passe -> {CEND}")
                connection_result = self.check_login(self.user, self.password)
                if connection_result[0]:
                    break
                else:
                    print(f"{CRED}{connection_result[2]}{CEND}")
                    if connection_result[1] == 3:
                        self.user = ""
                        self.password = ""
                    if connection_result[1] == 2:
                        self.password = ""

            telnet.write(f"{self.user}\n".encode('ascii'))
            telnet.write(f"{self.password}\n".encode('ascii'))

            if self.user == "RO":
                time.sleep(1)
                telnet.read_until(b">",15)
                telnet.write("\nen\n".encode('ascii'))

            telnet.read_until(b"#",15)
            telnet.write("\nshow run\n".encode('ascii'))
            
            with open("./bin/last-extracted-config.txt", "w") as file:
                while True:
                    line = telnet.read_until("#".encode('ascii'), 0.05)
                    file.write(line.decode())
                    telnet.write("\x20".encode('ascii'))
                    if line == b" ":
                        break
            
            telnet.write("\nexit\n".encode('ascii'))
            telnet.write("\x6C \n".encode('ascii'))
            telnet.close()

            # print(CGREEN + f"La configuration a été extraite du {self.ip} dans le fichier {self.path}" + CEND)
        except Exception as e:
            raise ValueError(f"{CRED} Une erreur est survenue lors de la récuperation de la configuration du switch {self.ip} {CEND}")

        self.filter_conf("./bin/last-extracted-config.txt")

    def extract_icl(self) -> None:
        '''
        Extracts Important Command Lines from the config.
        Takes the path of the config file to analyse as parameter.
        '''
        with open(self.path, "r") as config:
            for line in config:
                line = line.replace("\n","")
                for key in self.icl:
                    if "||" in key:
                        needle = key.split("||")
                        if needle[0] in line and needle[1] not in line:
                            self.icl[key] = line
                    else:
                        if key in line:
                            if isinstance(self.icl[key], str):
                                self.icl[key] = line
                            else:
                                self.icl[key].append(line)
        self.print_icl()
        self.filter_all_icl()

    def filter_all_icl(self) -> None:
        '''
        Filters the ICL dictionnary, in order to keep only the important data and remove commands.
        Example -> 'ip address switch 192.168.0.0' becomes '192.168.0.0'
        '''
        # IP ADDRESS
        self.icl["ip address"] = self.icl["ip address||netmask"].split("address")[1][1:]
        if "stack" not in self.icl["ip address"] and "switch" not in self.icl["ip address"]:
            self.icl["ip address"] = "switch " + self.icl["ip address"]
        self.icl.pop("ip address||netmask")
        # print(f"{CRED}{self.icl['ip address']}{CEND}")
        # self.site = ''.join(self.icl["ip address"].split(" ")).split(".")[-2]
        
        # GATEWAY
        if self.icl["ip default-gateway"] != "":
            self.icl["ip default-gateway"] = ''.join(re.findall(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", self.icl["ip default-gateway"]))

        # NETMASK
        if self.icl["ip address netmask"] != "":
            self.icl["ip address netmask"] = ''.join(re.findall(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", self.icl["ip address netmask"]))
        else:
            self.icl["ip address netmask"] = "255.255.255.0"

        # SNMP NAME
        if self.icl["snmp-server name"] != "":
            self.icl["snmp-server name"] = self.icl["snmp-server name"].split("\"")[1]

        # SNMP LOCATION
        if self.icl["snmp-server location"] != "":
            self.icl["snmp-server location"] = self.icl["snmp-server location"].split("\"")[1]

        # VLAN CREATE
        result = ""
        if self.icl["vlan create"] != "":
            for element in self.icl["vlan create"]:
                element = element.split(" ")
                result += element[2] + ","
                if element[3] == "name":
                    self.icl["vlan name"].append(f"vlan name {element[2]} {element[4]}")
        self.icl["vlan create"] = result[:-1]
                
        # VLAN NAMES
        result = {}
        for line in self.icl["vlan name"]:
            line = line.split(" ")
            vlan = line[2]
            name = line[3]

            name = name.split("-")
            self.site = name[-1]
            name = '-'.join(name)

            while len([char for char in name if char != '"']) > 16:
                name = str(input(f"Choisissez un nom de VLAN {CRED}plus court{CEND} ->"))
            
            result[vlan] = name
        self.icl["vlan name"] = result

        # VLAN MEMBERS
        result = {}
        
        for line in self.icl["vlan members"]:
            data = line.split(" ")[2:]
            vlan = data[0]

            # DECOMMENT IF YOU WANT TO CONVERT 1-3 PORTS TO 1,2,3
            # ports = self.get_ports(data[1])
            ports = data[1]

            if "," in vlan:
                temp = vlan.split(",")
                for element in temp:
                    result[element] = ports
            else:
                result[vlan] = ports   
        self.icl["vlan members"] = result

        # VLAN PORTS
        result = {}
        for line in self.icl["vlan ports"]:
            if "tagging" not in line:
                line = line.split(" ")
                vlan = line[-1]

                # DECOMMENT IF YOU WANT TO CONVERT 1-3 PORTS TO 1,2,3
                # ports = self.get_ports(line[2])
                ports = line[2]

                if vlan in result.keys():
                    result[vlan] += f",{ports}"
                else:
                    result[vlan] = ports    
        self.icl["vlan ports"] = result

        # VLAN MGMT
        self.icl["vlan mgmt"] = self.icl["vlan mgmt"].split(" ")[-1]

        # PORT NAMES 
        result = {}
        for line in self.icl["name port"]:
            line = line.split(" ", 3)
            name = line[3].replace("\"", "")
            port = line[2]
        
            port = f"1/{port}" if "/" not in port else port

            result[port] = name
        self.icl["name port"] = result

        # VOIP VLAN
        if self.site != "254":
            self.icl["lldp vlan voip"] = "200"
        else:
            self.icl["lldp vlan voip"] = ""
            # while True:
            #     try:
            #         self.icl["lldp vlan voip"] = int(input(f"{CBLUE} Quel est le numéro du VLAN VOIP de ce site? ( lldp ) {CEND}"))
            #         break
            #     except:
            #         print(f"{CRED} Numéro de vlan invalide. Reessayez. {CEND}")

        # TRUNKS
        result = []
        if self.icl["tagAll"] == "":
            self.icl["tagAll"] = str(input(f"{CBLUE} Quels sont les numéro des ports trunks? ( 1/1,1/50 etc... ) {CEND}"))
            for port in self.icl["tagAll"].split(","):
                result.append(port)
        else:
            for i in range(len(self.icl["tagAll"])):
                element = self.icl["tagAll"][i].split(" ")[2]
                if "/" not in element:
                    element = "1/" + element
                result.append(element)
        self.icl["tagAll"] = result
        
        # ADDING TRUNK PORT TO ALL VLANS, IF THE PORT ISN'T ALREADY PART OF THIS VLAN
        for vlan in self.icl["vlan create"].split(" ")[0].split(","):
            if vlan in self.icl["vlan members"]:
                ports = self.icl["vlan members"][vlan].split(",")
                trunks = self.icl["tagAll"]
                for trunk in trunks:
                    if trunk not in ports:
                        ports.insert(0, trunk)
                self.icl["vlan members"][vlan] = ','.join(ports)
        self.icl["tagAll"] = ''.join(self.icl["tagAll"])

    def suggest(self) -> None:
        suggestions = self.generate_suggestions()

        if self.include_suggestions == "print":
            for line in suggestions:
                print(line)
        elif self.include_suggestions == "file":
            with open(f"{self.path}/readme.txt", "w", encoding='utf-8') as file:
                for suggestion in suggestions:
                    file.write(f"{suggestion}\n")

    def generate_suggestions(self) -> list:
        if self.include_suggestions == "file":
            CEND = ""
            CBEIGE = ""

        suggestions = [
            f"{CBEIGE}Voici quelques précautions à prendre avant de mettre la nouvelle configuration sur le switch:\n",
            f"{CBEIGE}L'adresse IP spécifiée dans la configuration ( {CEND}{self.ip}{CBEIGE} ) est la même que sur l'ancien équipement.{CEND}",
            f"{CBEIGE}Assurez vous de déconnecter l'ancien switch avant de connecter le nouveau, afin d'éviter des adresses IP présents en double dans le réseau. {CEND}",
            f"{CBEIGE}Pensez à vérifier le numéro du VLAN VOIP spécifié dans la commande {CEND}lldp med-network-policies{CBEIGE}.{CEND}",
            f"{CBEIGE}Pensez à vérifier les noms des vlans, de sorte à ce qu'ils soient tous nommées de la même façon - {CEND}NUMERO-TYPE-NUMERO SITE{CBEIGE}.{CEND}\n",
        ]

        basic_suggestions_length = len(suggestions)

        if "stack" not in self.icl["ip address"] and "switch" not in self.icl["ip address"]:
            suggestions.append(f"{CBEIGE}Il semble que l'adresse IP ne possède pas de mot clé '{CEND}switch{CBEIGE}' ou '{CEND}stack{CBEIGE}'.{CEND}")
        
        if len(self.icl["snmp-server name"]) < 10:
            suggestions.append(f"{CBEIGE}Le snmp-server name '{CEND}{self.icl['snmp-server name']}{CBEIGE}' semble trop court.{CEND}")

        if len(self.icl["snmp-server location"]) < 20:
            suggestions.append(f"{CBEIGE}Le snmp-server location '{CEND}{self.icl['snmp-server location']}{CBEIGE}' semble trop court.{CEND}")
        
        if self.icl["lldp vlan voip"] == "" :
            suggestions.append(f"{CBEIGE}Le script n'as pas pu trouver le numéro du vlan VOIP, qui doit être spécifié dans la commande {CEND}lldp med-network-policies{CBEIGE}.{CEND}")

        if len(self.icl["vlan create"].split(",")) < 7:
            suggestions.append(f"{CBEIGE}Il semble que la liste des vlans ( {CEND}{self.icl['vlan create']}{CBEIGE} ) n'est pas complète.")

        if len(suggestions) != basic_suggestions_length:
            suggestions.insert(basic_suggestions_length, f"{CBEIGE}Informations complémentaires:\n{CEND}")

        return suggestions

    def generate_icl(self) -> None:
        with open("./bin/last-extracted-icl.json", "w") as file:
            file.write(json.dumps(self.icl, indent=4))

    def generate_config(self) -> None:
        '''
        Generates a complete configuration out of the ICL dictionnary.
        './bin/config_template.json' file is required to run this method.
        './bin/last-extracted-config.json' is the output file
        '''
        config = {}
        with open("./bin/config_template.json", "r") as file:
            config = json.load(file)

        for key in list(config.keys()):
            '''
            key -> json key
            temp_key -> key to icl dictionnary
            icl_key -> key inside an dictionnary of the icl dictionnary ( for example '100' in vlan members )
            '''
            if " - " in key:
                temp_key = key.split(" - ")[1]
                if isinstance(self.icl[temp_key], str):
                    '''
                    Replacing %'s in the config
                    '''
                    config_line = config[key]
                    value_to_insert = self.icl[temp_key]
                    result = config_line.replace("%", value_to_insert)
                else:
                    '''
                    Generating array's ( array of name port command, vlan members, etc... )
                    '''
                    result = {}
                    for icl_key in self.icl[temp_key]:
                        if temp_key == "vlan ports":
                            result[icl_key] = f"{temp_key} {self.icl[temp_key][icl_key]} pvid {icl_key}"
                        elif temp_key == "name port":
                            result[icl_key] = f'{temp_key} {icl_key} "{self.icl[temp_key][icl_key]}"'
                        else:
                            result[icl_key] = f"{temp_key} {icl_key} {self.icl[temp_key][icl_key]}"

                config[key] = result

        with open("./bin/last-generated-config.txt", "w") as file:
            for line in config.values():
                if isinstance(line, str):
                    file.write(line + "\n")
                elif isinstance(line, dict):
                    for value in line.values():
                        file.write(value + "\n")

    def push_config(self, com) -> None:
        '''
        Parameters:
            path ( str ) -> path to the configuration file
        Description:
            Writes the configuration from the configuration file to the switch via serial port.
            If any error occure while pushing the configuration, they will be printed for easier debug.
        '''

        with serial.Serial(port=com, baudrate=9600, timeout=1) as port, open(self.path, "r") as file:
            errors = []
            checks = ["Invalid", "No such", "Cannot", "Bad", "max", "address", "%", "Duplicated"]
            
            SwitcherUtils.send_serial(port, "\x19\r") #CTRL + Y
            SwitcherUtils.send_serial(port, "enable")
            SwitcherUtils.send_serial(port, "conf t")

            for command in file:
                SwitcherUtils.send_serial(port, command)
                result = SwitcherUtils.get_serial(port, 200)
                if any(code in result for code in checks):
                    errors.append((command, result))
                time.sleep(0.05)

            for error in errors:
                error[0].replace("\n", "")
                print(f"{CRED}Error generated by -> {CEND}{error[0]}")
                print(f"{CRED}Error description -> {CEND}{error[1]}")

    def print_icl(self) -> None:
        '''
        Prints ICL
        '''
        pprint(self.icl)

if __name__ == '__main__':
    SwitcherUtils.start()

    args = len(sys.argv)
    if args > 1:
        if args == 2:
            Switcher = Switcher(script=sys.argv[1])
        elif args == 3:
            Switcher = Switcher(path=sys.argv[2])
        else:
            Switcher = Switcher()
            
    SwitcherUtils.end()
