@ECHO OFF

cl.exe /nologo /MT /Ox /W0 /GS- /DNDEBUG /Tcbirdnet.c /link /OUT:birdnet.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj