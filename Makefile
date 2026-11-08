# ntrshd - RSH daemon for Windows NT
#
# Build:  nmake        (any SDK - NT 3.1, 3.5, 4.0 - and any CPU)
#
# One Makefile for the NT 3.1, 3.5 and 4.0 SDKs and every CPU.  Compile and
# link are driven through cl, which calls the right linker on each SDK
# (link32 on NT 3.1, link on 3.5/4.0), so the Makefile names neither the
# linker nor any architecture.  The libraries are listed in full because the
# NT 3.1 driver does not add the defaults (kernel32, the C runtime) itself;
# naming them again on 3.5/4.0 is harmless.
#
# Icon and version info live in ntrshd.rc; rc compiles it to ntrshd.res.
# NT 3.5 and 4.0 link that .res straight into the exe.  NT 3.1's link32
# cannot, so there cvtres first turns it into an object, ntrshd.rbj, for the
# CPU the SDK's CPU variable names.  The Makefile asks cl for its version to
# know which SDK it has, the same way as ntfetch.

# MSC = _MSC_VER of the cl in PATH: 800 NT 3.1 SDK, 900 VC++ 2.0, 1020 VC++ 4.2
!IF [echo MSC = _MSC_VER > msc.c] == 0 && [cl -nologo -EP -P msc.c > nul 2>&1] == 0
!INCLUDE msc.i
!ENDIF
!IF [del msc.?]
!ENDIF
!IFNDEF MSC
!ERROR cl not found
!ENDIF

# the SDK's setenv sets CPU: i386, MIPS or ALPHA
!IFNDEF CPU
CPU = i386
!ENDIF

!IF $(MSC) < 900
RES = ntrshd.rbj
!ELSE
RES = ntrshd.res
!ENDIF

# Visual C++ 4.x marks a program as made for Windows 4.0.  Mark it 3.10, as
# the NT 3.1 SDK and Visual C++ 2.0 do, so NT 3.5 starts it too.
!IF $(MSC) >= 1000
LFLAGS = /link /subsystem:console,3.10
!ENDIF

all: ntrshd.exe

ntrshd.res: ntrshd.rc ntrshd.ico
	rc -r ntrshd.rc

ntrshd.rbj: ntrshd.res
	cvtres -$(CPU) ntrshd.res -o ntrshd.rbj

ntrshd.exe: ntrshd.c $(RES)
	cl /nologo /O2 /MT ntrshd.c $(RES) kernel32.lib advapi32.lib wsock32.lib libcmt.lib $(LFLAGS)

clean:
	-del ntrshd.obj
	-del ntrshd.res
	-del ntrshd.rbj
	-del ntrshd.exe
