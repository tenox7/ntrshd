OBJS = rshd.obj rshd_rcp.obj Service.obj doexec.obj resource.res
LIBS = advapi32.lib user32.lib ws2_32.lib
CFLAGS = /O /nologo /DGAPING_SECURITY_HOLE

.cpp.obj:
	cl $(CFLAGS) /c $<

.c.obj:
	cl $(CFLAGS) /c $<

all: rshd.exe

clean:
	del $(OBJS)

rshd.exe: $(OBJS) Makefile
	link /nologo /subsystem:console $(OBJS) $(LIBS)

resource.res: resource.rc
	rc resource.rc


# EOF