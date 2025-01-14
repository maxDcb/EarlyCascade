#!/bin/bash

# first you need to compile inject-asm.x64.asm from a windows machine using:
# ML64 /c inject-asm.x64.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X64

x86_64-w64-mingw32-windres project.rc project.o
x86_64-w64-mingw32-gcc -Wl,-subsystem,windows -s -Os -Wno-narrowing implant.cpp helpers.cpp inject-asm.x64.obj -o ./bin/implant.exe -lstdc++ -static project.o -fpermissive

# x86_64-w64-mingw32-gcc -s -Os -Wno-narrowing implant.cpp helpers.cpp inject-asm.x64.obj -o ./bin/implant.exe -lstdc++ -static project.o -fpermissive

# x86_64-w64-mingw32-gcc implant.cpp inject-asm.x64.obj -o ./bin/implant.exe -lstdc++ -static

