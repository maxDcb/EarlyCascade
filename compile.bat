@ECHO OFF

:: syscall

ML64 /c inject-asm.x64.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X64
rc.exe project.rc
cl.exe -MT -Zp8 -c -nologo -Gy -Os -O1 -GR- -EHa -Oi -GS- implant.cpp helpers.cpp
link.exe /OUT:.\bin\implant.exe -nologo libvcruntime.lib libcmt.lib kernel32.lib winhttp.lib /MACHINE:X64 /SUBSYSTEM:WINDOWS inject-asm.x64.obj implant.obj helpers.obj project.res

@REM del *.obj

