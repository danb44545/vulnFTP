# vulnFTP
Deliberately vulnerable FTP Server for pentesting vanilla buffer overflows

# Compilation Options for Pelles C for vulnFTPServer.c:
Debug Information: Full
Warnings: Level1
Runtime Library: Single Threaded (LIB)
Calling convention: _cdecl
Optimizations: Speed
Machine: x86
Floating Point: Precise
Inlining: Default
C standard: C11
Options: Enable Microsoft extensions
Enable Pelles C extensions

Command line options (CCFlags)
-std:C11 -Tx86-coff -Zi -Ot -Ob1 -fp:precise -W1 -Gd -Ze -Zx

# Assembler Options for Pelles C for vulnFTPServer.c
Debug information: Full
Calling convention: cdecl
Machine: x86
Command Line Options (ASFLAGS)
-AIA32 -Zi -Gd

# Liner Options for Pelles C for vulnFTPServer.c
Debug Information: Codeview format
Subsystem Type: Console
Machine: x86
Command Line Options (LINKFLAGS)
-debug -debugtype:cv -subsystem:console -machine:x86 /SAFESEH:NO

#------------------------------------------------------------------
# vulnserver DLL
Need this piece in order to have a non SEH always loads at the same memory location piece

# Compilation options: same as above
# Assembler Options: same
# Linker options
Debug information: Codeview
Subsystem type: Windows
Library and object files: kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib advapi32.lib delayimp.lib
Machine: x86
Base Address: 0x64101000
Command Line Options (LINKFLAGS)
-subsystem:windows -machine:x86 -base:0x64101000 -dll /SAFESEH:No kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib advapi32.lib delayimp.lib




