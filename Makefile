all: ntrshd.exe

ntrshd.exe: ntrshd.c
	cl /nologo /O2 ntrshd.c wsock32.lib

clean:
	del ntrshd.exe
	del ntrshd.obj
