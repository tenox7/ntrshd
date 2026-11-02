# ntrshd - RSH daemon for Windows NT
#
# Build:  nmake              on NT 3.5, NT 4.0, and the RISC SDKs (MIPS/Alpha/PPC)
#         nmake NT31=1       on NT 3.1 only  (see the resource note below)
#
# One Makefile for the NT 3.1, 3.5 and 4.0 SDKs and every CPU.  Compile and
# link are driven through cl, which calls the right linker on each SDK
# (link32 on NT 3.1, link on 3.5/4.0), so the Makefile names neither the
# linker nor any architecture.  The libraries are listed in full because the
# NT 3.1 driver does not add the defaults (kernel32, the C runtime) itself;
# naming them again on 3.5/4.0 is harmless.
#
# Icon and version info live in ntrshd.rc; rc compiles it to ntrshd.res.
# NT 3.5 and 4.0 (and the RISC SDKs) link that .res straight into the exe, so
# plain "nmake" is all you need.  NT 3.1's older link32 cannot take a .res
# directly, so on NT 3.1 run "nmake NT31=1": that first converts the resource
# to an object (ntrshd.rbj) with cvtres.  NT 3.1 here is i386 only.

!ifdef NT31
RESOBJ = ntrshd.rbj
!else
RESOBJ = ntrshd.res
!endif

all: ntrshd.exe

ntrshd.res: ntrshd.rc ntrshd.ico
	rc -r ntrshd.rc

ntrshd.rbj: ntrshd.res
	cvtres -i386 ntrshd.res -o ntrshd.rbj

ntrshd.exe: ntrshd.c $(RESOBJ)
	cl /nologo /O2 /MT ntrshd.c $(RESOBJ) kernel32.lib advapi32.lib wsock32.lib libcmt.lib

clean:
	-del ntrshd.obj
	-del ntrshd.res
	-del ntrshd.rbj
	-del ntrshd.exe
